"""CLI: python3 -m forensics <session.jsonl...> --out DIR"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .brief import find_latest, render_brief
from .bundle import verify_file, write_bundle
from .graph import render_mermaid
from .ingest_claude import ingest_file as ingest_claude
from .ingest_cursor import ingest_file as ingest_cursor
from .ingest_droid import ingest_file as ingest_droid
from .ingest_evidence import ingest_file as ingest_evidence
from .ledger import DEFAULT_CLAUDE, DEFAULT_DROID, DEFAULT_KIMI
from .ingest_kimi import ingest_file as ingest_kimi
from .timeline import render

_KIMI_TYPES = {"turn.prompt", "context.append_loop_event", "permission.record_approval_result"}
_CURSOR_TYPES = {"system", "user", "thinking", "assistant", "tool_call", "result"}


def detect_format(path: Path) -> str:
    """Sniff the first dict row: 'claude', 'kimi', 'cursor', or 'evidence'."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                row = json.loads(line)
            except Exception:
                continue
            if isinstance(row, dict):
                if "entry_sha256" in row and "payload_schema_id" in row:
                    return "evidence"
                if row.get("type") in _KIMI_TYPES or "toolCallId" in row:
                    return "kimi"
                if row.get("type") in _CURSOR_TYPES and "session_id" in row:
                    return "cursor"
                if row.get("type") == "session_start" and "cwd" in row:
                    return "droid"
                if "sessionId" in row or "parentUuid" in row or row.get("type") in ("user", "assistant"):
                    return "claude"
    return "claude"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="forensics",
                                 description="reconstruct an agent session from native artifacts")
    ap.add_argument("inputs", nargs="*", type=Path,
                    help="native session files (claude/kimi jsonl, evidence transcripts)")
    ap.add_argument("--out", type=Path, help="output bundle dir")
    ap.add_argument("--graph-max", type=int, default=60,
                    help="max graph nodes before eliding (default 60)")
    ap.add_argument("--graph-all", action="store_true",
                    help="graph every event, no cap")
    ap.add_argument("--ledger-out", type=Path,
                    help="instead of a bundle: chain-index all sessions under "
                         "the roots into a ledger at this dir")
    ap.add_argument("--last", action="store_true",
                    help="use the newest session file across both roots")
    ap.add_argument("--brief", action="store_true",
                    help="print the one-page session brief (writes brief.md "
                         "when --out is given)")
    ap.add_argument("--claude-root", type=Path, default=DEFAULT_CLAUDE)
    ap.add_argument("--kimi-root", type=Path, default=DEFAULT_KIMI)
    ap.add_argument("--droid-root", type=Path, default=DEFAULT_DROID)
    a = ap.parse_args(argv)

    if a.ledger_out:
        from .ledger import build_ledger
        manifest = build_ledger(a.claude_root, a.kimi_root, a.ledger_out,
                                a.droid_root)
        ok = verify_file(a.ledger_out / "ledger.jsonl")
        print(f"forensics: ledger sessions={manifest['sessions']} "
              f"rows={manifest['rows']} chain={'OK' if ok else 'BROKEN'}")
        print(f"forensics: ledger at {a.ledger_out}")
        return 0 if ok else 2

    if a.last:
        found = find_latest(a.claude_root, a.kimi_root, a.droid_root)
        if found is None:
            print("forensics: no sessions under any root", file=sys.stderr)
            return 1
        a.inputs = [found[0]]

    if not a.inputs:
        ap.error("either INPUTS --out DIR, --last, or --ledger-out DIR "
                 "is required")

    events = []
    fmts = []
    for p in (a.inputs or []):
        if not p.is_file():
            print(f"forensics: no such file: {p}", file=sys.stderr)
            return 1
        fmt = detect_format(p)
        fmts.append(fmt)
        ingest = {"kimi": ingest_kimi, "evidence": ingest_evidence,
                  "cursor": ingest_cursor, "droid": ingest_droid}.get(fmt, ingest_claude)
        events.extend(ingest(p))
        print(f"forensics: {p.name}: format={fmt} events so far={len(events)}")
    events.sort(key=lambda e: (e.get("ts") or "", e["seq"]))
    fmt_label = fmts[0] if len(set(fmts)) == 1 else "mixed"

    if not a.out:
        if not a.brief:
            ap.error("--out DIR is required without --brief")
        import tempfile
        with tempfile.TemporaryDirectory(prefix="forensics-brief-") as td:
            from pathlib import Path as _P
            write_bundle(events, _P(td), list(a.inputs))
            ok = verify_file(_P(td) / "transcript.jsonl")
        print(render_brief(events, list(a.inputs), fmt_label, ok))
        return 0 if ok else 2

    manifest = write_bundle(events, a.out, list(a.inputs))
    timeline = render(events)
    (a.out / "timeline.md").write_text(timeline, encoding="utf-8")
    graph = render_mermaid(events, max_nodes=a.graph_max,
                           include_all=a.graph_all)
    (a.out / "graph.md").write_text(graph, encoding="utf-8")

    ok = verify_file(a.out / "transcript.jsonl")
    print(f"forensics: events={len(events)} rows={manifest['rows']} "
          f"chain={'OK' if ok else 'BROKEN'}")
    if a.brief:
        brief = render_brief(events, list(a.inputs), fmt_label, ok)
        (a.out / "brief.md").write_text(brief, encoding="utf-8")
        print(brief)
    else:
        from .explain import digest
        for line in digest(events):
            print(f"forensics: {line}")
    print(f"forensics: bundle at {a.out}")
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
