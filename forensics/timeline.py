"""Render a human timeline from a normalized event stream.

Answers the three IR questions in one page: what the agent was asked to
do (prompt rows), what it actually ran (tool calls with phase labels and
the rule that fired), and what crossed a boundary (egress + credential
touches + reads outside cwd). Wording stays descriptive: "matched rule",
never "attacker did".
"""
from __future__ import annotations

import re
from collections import Counter

def _cell(s: str, width: int = 120) -> str:
    """Markdown-table-safe cell: no pipes, no newlines (heredocs would
    otherwise inject headings/rows into the rendered timeline)."""
    return (s.replace("\n", "\\n").replace("\r", "").replace("|", "\\|"))[:width]


EGRESS_RE = re.compile(
    r"(curl|wget|nc|ncat|socat)[^;&|]*https?://|https?://\S+", re.I)
CRED_TOUCH_RE = re.compile(
    r"\.claude/\.credentials|\.codex/auth\.json|\.kimi-code/credentials|"
    r"\.aws/credentials|\.npmrc|\.docker/config\.json|kube?config|id_rsa|"
    r"\.netrc|credentials\.json|/var/run/secrets/", re.I)


def boundary_flags(command: str, cwd: str | None) -> list[str]:
    flags = []
    if command and EGRESS_RE.search(command):
        flags.append("network-egress")
    if command and CRED_TOUCH_RE.search(command):
        flags.append("credential-artifact")
    return flags


def boundary_flags_event(event: dict) -> list[str]:
    """Boundary flags over a normalized event (command and target aware)."""
    command = event.get("command") or ""
    cwd = event.get("cwd")
    flags = boundary_flags(command, cwd)
    if command and cwd:
        # crude read-outside-cwd signal for absolute paths in read commands
        for m in re.finditer(r"\b(?:cat|head|tail|cp|mv|rm)\b\s+(\S+)", command):
            target = m.group(1)
            if target.startswith(">"):
                continue
            if target.startswith("/") and not target.startswith(cwd):
                flags.append("read-outside-cwd")
                break
    target = event.get("target")
    if target and cwd and target.startswith("/") and not target.startswith(cwd):
        flags.append("path-outside-cwd")
    return flags


def render(events: list[dict], title: str = "agent session timeline") -> str:
    lines = [f"# {title}", ""]
    sessions = sorted({str(e.get("session")) for e in events if e.get("session")})
    cwds = sorted({str(e.get("cwd")) for e in events if e.get("cwd")})
    if sessions:
        lines.append(f"Sessions: {', '.join(sessions)}")
    if cwds:
        lines.append(f"Working dirs: {', '.join(cwds)}")
    lines.append(f"Events: {len(events)} "
                 f"(prompts {sum(1 for e in events if e['kind']=='user_prompt')}, "
                 f"tool calls {sum(1 for e in events if e['kind']=='tool_call')}, "
                 f"tool results {sum(1 for e in events if e['kind']=='tool_result')})")
    lines.append("")

    # plain-language shortlist + label meanings, then the detail tables
    from .explain import render_md
    lines.append(render_md(events))
    lines.append("")

    calls = [e for e in events if e["kind"] == "tool_call"]
    phase_counts = Counter(e["phase"] for e in calls if e.get("phase"))
    if phase_counts:
        lines.append("## Phase activity (matched rules)")
        lines.append("")
        lines.append("| phase | calls | first seen | last seen |")
        lines.append("|---|---|---|---|")
        for phase, n in phase_counts.most_common():
            ts_list = [e.get("ts") for e in calls
                       if e.get("phase") == phase and e.get("ts")]
            lines.append(f"| {phase} | {n} | {min(ts_list) or '-'} | {max(ts_list) or '-'} |")
        lines.append("")

    boundary_rows = []
    for e in calls:
        flags = boundary_flags_event(e)
        if flags:
            boundary_rows.append((e, flags))
    if boundary_rows:
        lines.append("## Boundary events")
        lines.append("")
        lines.append("| ts | tool | flags | command (first 120) |")
        lines.append("|---|---|---|---|")
        for e, flags in boundary_rows[:200]:
            cmd = _cell(e.get("command") or "")
            lines.append(f"| {e.get('ts') or '-'} | {e.get('tool') or '-'} | "
                         f"{', '.join(flags)} | `{cmd}` |")
        lines.append("")

    approvals = [e for e in events if e["kind"] == "approval"]
    if approvals:
        from collections import Counter as _C
        dec = _C(f"{a.get('decision')}/{a.get('scope')}" for a in approvals)
        lines.append("## Approval ledger (native, kimi only)")
        lines.append("")
        for combo, n in dec.most_common():
            lines.append(f"- {combo}: {n}")
        call_by_id = {e.get("tool_call_id"): e for e in calls}
        auto_flagged = []
        for a in approvals:
            if a.get("scope") == "session":
                linked = call_by_id.get(a.get("tool_call_id"))
                if linked and linked.get("phase"):
                    auto_flagged.append((a, linked))
        if auto_flagged:
            lines.append("")
            lines.append("Session-scoped approvals of phase-matched commands"
                         " (auto-approved for the rest of the session):")
            lines.append("")
            for a, linked in auto_flagged[:50]:
                cmd = _cell(linked.get("command") or "")
                lines.append(f"- `{cmd}` — {linked.get('phase')} "
                             f"({linked.get('rule')})")
        lines.append("")

    controls = [e for e in events if e["kind"] == "control"]
    if controls:
        lines.append(f"## Human interventions: "
                     f"{len(controls)} ("
                     + ", ".join(f"{name} x{n}" for name, n in
                                 Counter(c.get("control") for c in controls).items())
                     + ")")
        lines.append("")

    if calls:
        lines.append("## Tool call stream (first 400)")
        lines.append("")
        lines.append("| ts | tool | phase | rule | sidechain | command (first 100) |")
        lines.append("|---|---|---|---|---|---|")
        for e in calls[:400]:
            cmd = _cell(e.get("command") or "", 100)
            lines.append(
                f"| {e.get('ts') or '-'} | {e.get('tool') or '-'} | "
                f"{e.get('phase') or '-'} | {e.get('rule') or '-'} | "
                f"{'yes' if e.get('sidechain') else 'no'} | `{cmd}` |")
        lines.append("")
    lines.append("Labels are deterministic rule matches over reconstructed "
                 "commands. They are classifications, not accusations.")
    lines.append("")
    return "\n".join(lines)
