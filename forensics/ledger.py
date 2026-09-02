"""Chain-index every local agent session into one tamper-evident ledger.

One row per session file (claude or kimi), chained with the same
construction as every other forensics bundle. This is rule-32
infrastructure: hunt records can cite ledger rows (source sha256 + time
range + activity histogram) as tamper-evident receipts of the sessions a
hunt ran in, without copying any session content.

Paths are sanitized (home -> ~) so a ledger never carries the operator's
username. Aggregates only: counts, hashes, timestamps. No content.
"""
from __future__ import annotations

import json
from pathlib import Path

from .bundle import GENESIS, BundleWriter
from .canonical import entry_hash, payload_hash
from .canonical import sha256_bytes
from .ingest_claude import ingest_file as ingest_claude
from .ingest_kimi import ingest_file as ingest_kimi

DEFAULT_CLAUDE = Path.home() / ".claude" / "projects"
DEFAULT_KIMI = Path.home() / ".kimi-code" / "sessions"


def _sanitize(path, replacements=None) -> str:
    s = str(path)
    for prefix, sub in sorted(replacements or [(str(Path.home()), "~")],
                              key=lambda t: -len(t[0])):
        if s.startswith(prefix):
            s = s.replace(prefix, sub, 1)
            break
    # the home basename can survive inside names (e.g. kimi workspace dirs
    # like wd_<user>_hash); scrub it wherever it appears
    return s.replace(Path.home().name, "user")


def _replacements_for(roots) -> list[tuple[str, str]]:
    reps = [(str(Path.home()), "~")]
    reps += [(str(r), "~/" + r.name) for r in roots]
    return sorted(reps, key=lambda t: -len(t[0]))


def _summarize(path: Path, fmt: str, ingest, reps) -> dict:
    events = ingest(path)
    kinds: dict[str, int] = {}
    phases: dict[str, int] = {}
    ts_list = []
    sessions = set()
    cwds = set()
    for e in events:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
        if e["kind"] == "tool_call" and e.get("phase"):
            phases[e["phase"]] = phases.get(e["phase"], 0) + 1
        if e.get("ts"):
            ts_list.append(e["ts"])
        if e.get("session"):
            sessions.add(str(e["session"]))
        cwd = e.get("cwd")
        if cwd:
            cwds.add(_sanitize(cwd, reps))
    return {
        "path": _sanitize(path, reps),
        "format": fmt,
        "sha256": sha256_bytes(path.read_bytes()),
        "bytes": path.stat().st_size,
        "mtime": int(path.stat().st_mtime),
        "events": len(events),
        "kinds": dict(sorted(kinds.items())),
        "phases": dict(sorted(phases.items())),
        "sessions": sorted(sessions)[:5],
        "cwds": sorted(cwds)[:5],
        "first_ts": min(ts_list) if ts_list else None,
        "last_ts": max(ts_list) if ts_list else None,
    }


def build_ledger(claude_root: Path | None, kimi_root: Path | None,
                 out_dir: Path) -> dict:
    roots = []
    if claude_root:
        roots.append((claude_root, "claude", "*/*.jsonl", ingest_claude))
    if kimi_root:
        roots.append((kimi_root, "kimi", "*/*/agents/*/wire.jsonl", ingest_kimi))
    reps = _replacements_for([r for r, _, _, _ in roots])
    w = BundleWriter([])
    w.add("run_start", {
        "tool": "agent-forensics-ledger",
        "version": "0.1.0",
        "roots": [_sanitize(r, reps) for r, _, _, _ in roots],
        "note": "aggregate-only session index; no session content; paths sanitized",
    }, "forensics/ledger_start/1")  # ts set after summaries are computed
    summaries = []
    for root, fmt, pattern, ingest in roots:
        if not root.is_dir():
            continue
        files = sorted(p for p in root.glob(pattern) if p.is_file())
        for p in files:
            try:
                s = _summarize(p, fmt, ingest, reps)
            except Exception as exc:  # never let one bad file kill the ledger
                s = {"path": _sanitize(p, reps), "format": fmt, "error": str(exc)[:200],
                     "sha256": sha256_bytes(p.read_bytes()),
                     "bytes": p.stat().st_size}
            summaries.append(s)
            w.add("session_summary", s, "forensics/session_summary/1",
                  ts=s.get("first_ts"))
    w.add("run_end", {"sessions": len(summaries)}, "forensics/ledger_end/1",
          ts=max((s.get("last_ts") for s in summaries if s.get("last_ts")),
                 default=None))
    # backfill the genesis row's ts with the ledger's earliest session ts
    # (rows[0] is run_start; rewriting its ts changes entry_hash, so the
    # whole chain must be recomputed after this point deterministically)
    first = min((s.get("first_ts") for s in summaries if s.get("first_ts")),
                default=None)
    w.rows[0]["payload"] = dict(w.rows[0]["payload"])
    w.rows[0]["ts"] = first
    for row in w.rows:
        row["payload_sha256"] = payload_hash(row["payload"])
        row["entry_sha256"] = entry_hash(row)
    prev = None
    for i, row in enumerate(w.rows):
        row["prev_sha256"] = GENESIS if i == 0 else prev
        row["entry_sha256"] = entry_hash(row)
        prev = row["entry_sha256"]
    assert w.verify(), "ledger chain broken before write"
    out_dir.mkdir(parents=True, exist_ok=True)
    ledger = out_dir / "ledger.jsonl"
    with open(ledger, "w", encoding="utf-8") as fh:
        for row in w.rows:
            fh.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    manifest = {
        "ledger_sha256": sha256_bytes(ledger.read_bytes()),
        "sessions": len(summaries),
        "rows": len(w.rows),
        "roots": [_sanitize(r, reps) for r, _, _, _ in roots],
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest
