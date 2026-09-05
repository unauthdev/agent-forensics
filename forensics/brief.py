"""Democratized session brief: what was built, run, crossed, worth a look.

Deterministic only. No model calls. Verdict-free language throughout:
"matched rule", never "attacker did". Paths sanitized (home -> ~).
Prompts and prose are hashed upstream and never re-emitted here.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from .canonical import sha256_bytes
from .explain import RANK_NAMES, review_first
from .ledger import DEFAULT_CLAUDE, DEFAULT_DROID, DEFAULT_KIMI
from .timeline import boundary_flags_event


def _sanitize(s: str | None) -> str:
    if not s:
        return "-"
    home = str(Path.home())
    out = s.replace(home, "~")
    # Always scrub the bare username too: slugs and residual path
    # fragments keep it even after the home replacement above
    # (privacy-first: over-matching a name is fine, leaking is not).
    return out.replace(Path.home().name, "user")


def find_latest(claude_root: Path | None = None,
                kimi_root: Path | None = None,
                droid_root: Path | None = None) -> tuple[Path, str] | None:
    """Newest session file by mtime across all roots. None when empty."""
    claude_root = claude_root or DEFAULT_CLAUDE
    kimi_root = kimi_root or DEFAULT_KIMI
    droid_root = droid_root if droid_root is not None else DEFAULT_DROID
    cands: list[tuple[float, Path, str]] = []
    if claude_root and claude_root.is_dir():
        cands += [(p.stat().st_mtime, p, "claude")
                  for p in claude_root.glob("*/*.jsonl") if p.is_file()]
    if kimi_root and kimi_root.is_dir():
        cands += [(p.stat().st_mtime, p, "kimi")
                  for p in kimi_root.glob("*/*/agents/*/wire.jsonl") if p.is_file()]
    if droid_root and droid_root.is_dir():
        cands += [(p.stat().st_mtime, p, "droid")
                  for p in droid_root.glob("*/*.jsonl") if p.is_file()]
    if not cands:
        return None
    cands.sort(key=lambda t: (t[0], str(t[1])))
    _, path, fmt = cands[-1]
    return path, fmt


def render_brief(events: list[dict], sources: list[Path], fmt: str,
                 chain_ok: bool, limit: int = 5) -> str:
    """One-page markdown brief. Deterministic, verdict-free."""
    calls = [e for e in events if e.get("kind") == "tool_call"]
    prompts = sum(1 for e in events if e["kind"] == "user_prompt")
    results = sum(1 for e in events if e["kind"] == "tool_result")
    tss = sorted(e.get("ts") for e in events if e.get("ts"))
    window = f"{tss[0]}..{tss[-1]}" if tss else "-"

    # glob hits are read-shaped patterns, never built files
    built = sorted({_sanitize(e.get("target")) for e in calls
                    if e.get("target") and e.get("tool") != "glob"})
    ran = [e for e in calls if (e.get("command") or "").strip()]
    tools = Counter(e.get("tool") or "?" for e in calls)
    flags = Counter(f for c in calls for f in boundary_flags_event(c))
    short = review_first(events, limit=limit, per_rule=2)

    lines = ["# Session brief", ""]
    if len(sources) == 1:
        lines.append(f"Source: `{_sanitize(str(sources[0]))}` ({fmt}), "
                     f"chain {'OK' if chain_ok else 'BROKEN'}")
    else:
        lines.append(f"Sources: {len(sources)} files ({fmt}, first: "
                     f"`{_sanitize(str(sources[0]))}`), "
                     f"chain {'OK' if chain_ok else 'BROKEN'}")
    lines.append(f"Scale: {len(events)} events, {prompts} prompts, "
                 f"{len(calls)} tool calls, {results} results, window {window}")
    lines.append("")
    lines.append(f"## Built ({len(built)} files)")
    lines.append("")
    if built:
        lines += [f"- `{b}`" for b in built[:20]]
        if len(built) > 20:
            lines.append(f"- ...and {len(built) - 20} more (timeline.md has all)")
    else:
        lines.append("No file targets recorded in this session.")
    lines.append("")
    lines.append(f"## Ran ({len(ran)} commands)")
    lines.append("")
    if tools:
        lines.append("By tool: " + ", ".join(
            f"{t} {n}" for t, n in tools.most_common(8)))
        lines.append("")
    if ran:
        seen: list[str] = []
        for e in ran:
            cmd = _sanitize(e.get("command") or "").replace("\n", "\\n")[:100]
            if cmd not in seen:
                seen.append(cmd)
            if len(seen) >= 8:
                break
        lines += [f"- `{c}`" for c in seen]
    else:
        lines.append("No shell commands recorded.")
    lines.append("")
    lines.append("## Crossed a boundary" +
                 (" (none)" if not flags else ""))
    lines.append("")
    if flags:
        lines.append("Counts: " + ", ".join(
            f"{k} {v}" for k, v in flags.most_common(4)))
        lines.append("")
        n = 0
        for e in calls:
            fl = boundary_flags_event(e)
            if not fl:
                continue
            cmd = _sanitize((e.get("command") or e.get("target") or "")) \
                .replace("\n", "\\n").replace("|", "\\|")[:110]
            lines.append(f"- `{e.get('ts') or '-'}` {', '.join(fl)}: `{cmd}` "
                         f"({e.get('phase') or '-'}/{e.get('rule') or '-'})")
            n += 1
            if n >= 10:
                break
    else:
        lines.append("No network-egress, credential-artifact, or "
                     "outside-cwd flags matched.")
    lines.append("")
    lines.append("## Worth a look (read first, not a verdict)")
    lines.append("")
    if short:
        for i, item in enumerate(short, 1):
            cmd = _sanitize(item["command"]) \
                .replace("\n", "\\n").replace("|", "\\|")[:110]
            lines.append(f"{i}. {RANK_NAMES[item['rank']]} - "
                         f"{item['phase'] or '-'}/{item['rule'] or '-'}: "
                         f"{item['why']}")
            lines.append(f"   `{cmd}`")
    else:
        lines.append("Quiet session: no credential touches, outside-cwd "
                     "paths, or high-risk matches.")
    lines.append("")
    try:
        sha = sha256_bytes(sources[0].read_bytes())[:16]
        extra = "" if len(sources) == 1 else f" (+{len(sources) - 1} more files)"
        lines.append(f"Receipt: sha256 {sha}...{extra}, "
                     f"{len(events)} events. Labels are deterministic rule "
                     f"matches over reconstructed commands - "
                     f"classifications, not accusations.")
    except OSError:
        lines.append("Receipt: source unreadable for hashing. "
                     "Labels are classifications, not accusations.")
    lines.append("")
    return "\n".join(lines)
