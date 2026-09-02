"""Render the normalized event stream as a Mermaid causal DAG.

The graph is the structural view of what the timeline is the tabular view
of: nodes are events, edges follow the observed causal chain (parentUuid
in claude sessions, parentUuid/toolCallId in kimi wire logs, parent_seq
in evidence transcripts). Phase-matched tool calls are colored by phase;
boundary crossings get a red stroke; approvals and human interventions
(steer/cancel) are distinct shapes, because "a human touched the loop
here" is exactly the fact an incident review wants to see.

Deterministic: same events, same graph. Node labels are sanitized
(quotes, brackets, newlines stripped) and truncated.
"""
from __future__ import annotations

import re
from pathlib import Path

from .explain import review_first
from .timeline import boundary_flags_event

PHASE_CLASSES = {
    "recon", "credential-access", "evasion", "exfil", "dropper",
    "c2", "k8s", "supply-chain", "pivot",
}

_CLASS_DEFS = [
    "classDef prompt fill:#e9ecef,stroke:#adb5bd",
    "classDef boundary stroke:#d62828,stroke-width:3px",
    "classDef approval fill:#ffe8a3,stroke:#f4a261",
    "classDef control fill:#cdd7e1,stroke:#5c6c7c",
    "classDef reviewfirst fill:#ffccd5,stroke:#c92a2a,stroke-width:4px",
    "classDef elided fill:#f1f3f5,stroke:#ced4da,stroke-dasharray: 4",
] + [
    f"classDef {p} fill:{c}" for p, c in [
        ("recon", "#fde2c4"), ("credential-access", "#ffc9c9"),
        ("evasion", "#d0bfff"), ("exfil", "#ffd8a8"),
        ("dropper", "#bac8ff"), ("c2", "#b2f2bb"),
        ("k8s", "#a5d8ff"), ("supply-chain", "#eebefa"),
        ("pivot", "#ffec99"),
    ]
]


def _label(text: str, width: int = 60) -> str:
    s = str(text or "").replace(str(Path.home()), "~")
    s = re.sub(r"\s+", " ", s).strip()
    s = s.replace('"', "'").replace("[", "(").replace("]", ")")
    return (s[:width] + "...") if len(s) > width else s


def _priority(e: dict) -> int:
    """Lower = more likely to survive the node cap."""
    if e["kind"] == "tool_call" and (e.get("phase") or boundary_flags_event(e)):
        return 0
    if e["kind"] == "approval":
        return 1
    if e["kind"] == "control":
        return 2
    if e["kind"] == "user_prompt":
        return 3
    if e["kind"] == "tool_result":
        return 5
    return 6


def _select(events: list[dict], max_nodes: int, include_all: bool,
            protect: set | None = None) -> tuple[list[dict], int]:
    protect = protect or set()
    if include_all or len(events) <= max_nodes:
        return events, 0
    # read-first shortlist survives the cap even if unremarkable by score
    kept: dict = {}
    for e in sorted(events, key=lambda e: (_priority(e), e["seq"])):
        if len(kept) >= max_nodes and e["seq"] not in protect:
            break
        kept[e["seq"]] = e
    keep = [e for e in events if e["seq"] in kept]
    keep_ids = {e["seq"] for e in keep}
    by_seq = {e["seq"]: e for e in events}
    # close the ancestor chain so kept nodes stay connected
    for e in list(keep):
        p = e.get("parent")
        hops = 0
        while p is not None and p not in keep_ids and hops < 32:
            anc = by_seq.get(p)
            if anc is None:
                break
            keep.append(anc)
            keep_ids.add(anc["seq"])
            p = anc.get("parent")
            hops += 1
    keep.sort(key=lambda e: e["seq"])
    return keep, len(events) - len({e["seq"] for e in keep})


def render_mermaid(events: list[dict], max_nodes: int = 60,
                   include_all: bool = False, title: str = "session graph") -> str:
    short = review_first(events, limit=10)
    rf = {item["seq"] for item in short}
    kept, elided = _select(events, max_nodes, include_all, protect=rf)
    rf_kept = rf & {e["seq"] for e in kept}
    by_seq = {e["seq"]: e for e in kept}
    calls_by_id = {e.get("tool_call_id"): e for e in kept
                   if e["kind"] == "tool_call" and e.get("tool_call_id")}
    lines = [f"%% {title} (deterministic; labels are rule matches, not accusations)",
             "graph TD"]
    emitted = set()
    class_stmts = []
    def node(e: dict) -> str:
        nid = f"e{e['seq']}"
        if nid in emitted:
            return nid
        emitted.add(nid)
        kind = e["kind"]
        classes = []
        if kind == "user_prompt":
            label = f"prompt {_label(e.get('prompt_sha256') or '', 8)}"
            classes.append("prompt")
        elif kind == "tool_call":
            cmd = e.get("command") or e.get("target") or ""
            label = f"{e.get('tool') or 'tool'}: {_label(cmd)}" if cmd else (e.get("tool") or "tool")
            if e.get("phase") in PHASE_CLASSES:
                classes.append(e["phase"])
            if boundary_flags_event(e):
                classes.append("boundary")
            if e["seq"] in rf_kept:
                classes.append("reviewfirst")
        elif kind == "tool_result":
            label = f"result {_label(e.get('result_sha256') or '', 8)}"
        elif kind == "approval":
            label = f"approval {e.get('decision')}/{e.get('scope')}"
            classes.append("approval")
        elif kind == "control":
            label = f"human: {e.get('control')}"
            classes.append("control")
        else:
            label = _label(kind)
        if len(classes) == 1:
            lines.append(f'    {nid}["{label}"]:::{classes[0]}')
        else:
            # multi-class nodes use the class statement (portable mermaid)
            lines.append(f'    {nid}["{label}"]')
            class_stmts.append(f"class {nid} {','.join(classes)}")
        return nid
    for e in kept:
        nid = node(e)
        parent = e.get("parent")
        if parent is not None and parent in by_seq and parent != e["seq"]:
            lines.append(f"    {node(by_seq[parent])} --> {nid}")
        if e["kind"] == "approval":
            linked = calls_by_id.get(e.get("tool_call_id"))
            if linked is not None:
                lines.append(f"    {nid} -.approves.-> {node(linked)}")
    if elided:
        lines.append(f'    E1["{elided} events elided (raise --graph-max or use --graph-all)"]:::elided')
    # order edges: connect consecutive kept events whose causal parent was
    # elided, so a capped graph still reads as a path (dotted, labeled)
    edge_keys = {tuple(l.strip().split()[0:1]) for l in lines if "-->" in l}
    seqs = [e["seq"] for e in kept]
    for a, b in zip(seqs, seqs[1:]):
        has_causal = any(l.strip().startswith(f"e{a} ") and "-->" in l for l in lines)
        b_parent = by_seq.get(b, {}).get("parent") if isinstance(by_seq.get(b), dict) else None
        if b_parent not in by_seq and not has_causal:
            lines.append(f"    e{a} -. order .-> e{b}")
    lines.extend("    " + c for c in class_stmts)
    lines.extend("    " + d for d in _CLASS_DEFS)
    legend = [
        f"# {title}",
        "",
        "Red fill with a thick stroke = read-first shortlist (credential "
        "touch, path outside the working dir, or egress on a high-risk "
        "match). That is a ranking for review, never a verdict. Red "
        "stroke alone = other boundary crossing. Dotted arrows = "
        "approvals (labeled) or reading order. Node class names are the "
        "phase labels from the timeline.",
        "",
        "```mermaid",
    ]
    return "\n".join(legend + lines) + "\n```\n"
