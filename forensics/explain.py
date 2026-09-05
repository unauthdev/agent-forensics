"""Deterministic ranking of what a review should read first.

No model, no magic scoring: a fixed priority order picks at most N tool
calls -- credential-artifact touches first, then paths outside the
session's working dir, then network egress on a high-risk phase, then
high-risk phases without egress -- each annotated with the canned rule
explanation from phases.RULE_HELP. Highlighted means "read this one
first"; it is never "this is an attack". The caveat travels with every
render that uses these functions.
"""
from __future__ import annotations

from collections import Counter

from .phases import rule_help
from .timeline import boundary_flags_event

HIGH_RISK = frozenset({"credential-access", "c2", "exfil", "supply-chain"})

RANK_NAMES = {
    0: "credential-touch",
    1: "outside-cwd",
    2: "egress+high-risk",
    3: "high-risk-match",
}


def _rank(e: dict, flags: list[str]) -> int | None:
    if "credential-artifact" in flags:
        return 0
    if "path-outside-cwd" in flags or "read-outside-cwd" in flags:
        return 1
    if e.get("phase") in HIGH_RISK and "network-egress" in flags:
        return 2
    if e.get("phase") in HIGH_RISK:
        return 3
    return None


def review_first(events: list[dict], limit: int = 10,
                  per_rule: int = 4) -> list[dict]:
    """Priority-ordered shortlist of tool calls for a human review.

    At most per_rule items per rule id, so one dominant pattern cannot
    fill every slot and hide the breadth below it.
    """
    ranked = []
    for e in events:
        if e.get("kind") != "tool_call":
            continue
        flags = boundary_flags_event(e)
        rank = _rank(e, flags)
        if rank is None:
            continue
        ranked.append((rank, e.get("ts") or "", e["seq"], e, flags))
    ranked.sort(key=lambda t: (t[0], t[1], t[2]))
    seen: dict = {}
    out = []
    for rank, ts, seq, e, flags in ranked:
        key = e.get("rule") or RANK_NAMES[rank]
        if seen.get(key, 0) >= per_rule:
            continue
        seen[key] = seen.get(key, 0) + 1
        out.append({
            "ts": ts,
            "seq": seq,
            "tool": e.get("tool"),
            "phase": e.get("phase"),
            "rule": e.get("rule"),
            "flags": flags,
            "rank": rank,
            "command": (e.get("command") or e.get("target") or ""),
            "why": rule_help(e.get("rule") or ""),
        })
        if len(out) >= limit:
            break
    return out


def digest(events: list[dict]) -> list[str]:
    """Three stdout lines: scale, labels, shortlist. Verdict-free."""
    calls = [e for e in events if e.get("kind") == "tool_call"]
    phases = Counter(c["phase"] for c in calls if c.get("phase"))
    flags = Counter(f for c in calls for f in boundary_flags_event(c))
    tss = sorted(e.get("ts") for e in events if e.get("ts"))
    window = f"{tss[0]}..{tss[-1]}" if tss else "-"
    line1 = (f"digest: {len(events)} events, {len(calls)} tool calls, "
             f"window {window}")
    if phases:
        line2 = "phases: " + ", ".join(f"{p} {n}" for p, n in
                                       phases.most_common(8))
    else:
        line2 = f"phases: none of {len(calls)} commands matched a rule"
    line2 += " (rule matches, not verdicts)"
    short = review_first(events)
    if short:
        causes = Counter(RANK_NAMES[i["rank"]] for i in short)
        line3 = ("read first: " + ", ".join(f"{k} {v}" for k, v in
                                            causes.most_common())
                 + " (timeline.md has the list)")
    else:
        line3 = ("read first: none - no credential touches, outside-cwd "
                 "paths, or high-risk matches")
    if flags:
        line3 += f" | boundaries: " + ", ".join(
            f"{k} {v}" for k, v in flags.most_common(4))
    return [line1, line2, line3]


def render_md(events: list[dict], limit: int = 10,
              per_rule: int = 4) -> str:
    """Sections prepended to the timeline: shortlist + label meanings."""
    calls = [e for e in events if e.get("kind") == "tool_call"]
    lines: list[str] = []
    short = review_first(events, limit=limit, per_rule=per_rule)
    lines.append("## Read this first")
    lines.append("")
    if short:
        lines.append("Ranked shortlist for review - credential touches, "
                     "then paths outside the working dir, then egress on "
                     "high-risk matches; at most " + str(per_rule) +
                     " per rule so one pattern cannot hide the rest. "
                     "Highlighted means read this one first; it is not a "
                     "verdict.")
        lines.append("")
        for i, item in enumerate(short, 1):
            cmd = (item["command"].replace("\n", "\\n").replace("|", "\\|"))[:110]
            lines.append(f"{i}. `{item['ts'] or '-'}` - "
                         f"{RANK_NAMES[item['rank']]} - "
                         f"{item['phase'] or '-'}/{item['rule'] or '-'}: "
                         f"{item['why']}")
            lines.append(f"   `{cmd}`")
    else:
        lines.append("Nothing met the review filters: no credential "
                     "touches, no paths outside the working dir, no "
                     "high-risk matches.")
    lines.append("")
    fired = Counter((c["phase"], c["rule"]) for c in calls if c.get("rule"))
    if fired:
        lines.append("## What the labels mean")
        lines.append("")
        lines.append("| phase | calls | rule | why it matched |")
        lines.append("|---|---|---|---|")
        for (phase, rule), n in sorted(fired.items()):
            lines.append(f"| {phase} | {n} | {rule} | {rule_help(rule)} |")
        lines.append("")
    return "\n".join(lines)
