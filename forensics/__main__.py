"""CLI: python3 -m forensics <session.jsonl...> --out DIR"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .bundle import verify_file, write_bundle
from .graph import render_mermaid
from .ingest_claude import ingest_file as ingest_claude
from .ingest_evidence import ingest_file as ingest_evidence
from .ledger import DEFAULT_CLAUDE, DEFAULT_KIMI
from .ingest_kimi import ingest_file as ingest_kimi
from .timeline import render

_KIMI_TYPES = {"turn.prompt", "context.append_loop_event", "permission.record_approval_result"}


def detect_format(path: Path) -> str:
    """Sniff the first dict row: 'claude', 'kimi', or 'evidence'."""
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
    ap.add_argument("--claude-root", type=Path, default=DEFAULT_CLAUDE)
    ap.add_argument("--kimi-root", type=Path, default=DEFAULT_KIMI)
    a = ap.parse_args(argv)

    if a.ledger_out:
        from .ledger import build_ledger
        manifest = build_ledger(a.claude_root, a.kimi_root, a.ledger_out)
        ok = verify_file(a.ledger_out / "ledger.jsonl")
        print(f"forensics: ledger sessions={manifest['sessions']} "
              f"rows={manifest['rows']} chain={'OK' if ok else 'BROKEN'}")
        print(f"forensics: ledger at {a.ledger_out}")
        return 0 if ok else 2

    if not a.inputs or not a.out:
        ap.error("either INPUTS --out DIR or --ledger-out DIR is required")

    events = []
    for p in a.inputs:
        if not p.is_file():
            print(f"forensics: no such file: {p}", file=sys.stderr)
            return 1
        fmt = detect_format(p)
        ingest = {"kimi": ingest_kimi, "evidence": ingest_evidence}.get(fmt, ingest_claude)
        events.extend(ingest(p))
        print(f"forensics: {p.name}: format={fmt} events so far={len(events)}")
    events.sort(key=lambda e: (e.get("ts") or "", e["seq"]))

    manifest = write_bundle(events, a.out, a.inputs)
    timeline = render(events)
    (a.out / "timeline.md").write_text(timeline, encoding="utf-8")
    graph = render_mermaid(events, max_nodes=a.graph_max,
                           include_all=a.graph_all)
    (a.out / "graph.md").write_text(graph, encoding="utf-8")

    ok = verify_file(a.out / "transcript.jsonl")
    from .explain import digest
    print(f"forensics: events={len(events)} rows={manifest['rows']} "
          f"chain={'OK' if ok else 'BROKEN'}")
    for line in digest(events):
        print(f"forensics: {line}")
    print(f"forensics: bundle at {a.out}")
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
