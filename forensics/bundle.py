"""Emit a forensic bundle: hash-chained transcript + source manifest.

Chain construction matches the public sample format exactly
(forensics/canonical.py). Rows are forensic observations about artifacts,
never claims about live behavior: actor=forensics, vantage names the
artifact kind, parent_seq preserves the causal chain observed in the
source (parentUuid), seq is emission order.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .canonical import entry_hash, payload_hash, sha256_bytes

ACTOR = "forensics"
GENESIS = "0" * 64  # agent-evidence-0.2 chains seed prev_sha256 with 64 zeros

# Deterministic stand-in when a row has no source timestamp: bundle-level
# rows carry the bundle's own event window; build time NEVER enters the
# chain (it lives only in manifest.generated, which is unchained), so
# identical inputs rebuild byte-identical transcripts.
UNKNOWN_TS = "1970-01-01T00:00:00.000Z"


def _ts_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class BundleWriter:
    def __init__(self, sources: list[Path]):
        self.rows = []
        self.seq = 0
        self.prev = GENESIS
        self.sources = sources

    def add(self, type_: str, payload: dict, schema_id: str, *,
            parent_seq=None, ts=None, tool_call_id=None, truncated=False) -> int:
        self.seq += 1
        row = {
            "actor": ACTOR,
            "bytes_total": None,
            "entry_sha256": None,
            "full_sha256": None,
            "parent_seq": parent_seq,
            "payload": payload,
            "payload_schema_id": schema_id,
            "payload_sha256": payload_hash(payload),
            "prev_sha256": self.prev,
            "seq": self.seq,
            "tool_call_id": tool_call_id,
            "truncated": truncated,
            "ts": ts if ts is not None else UNKNOWN_TS,
            "type": type_,
            "vantage": "artifact:claude-code-session",
        }
        digest = entry_hash(row)
        row["entry_sha256"] = digest
        self.rows.append(row)
        self.prev = digest
        return self.seq

    def source_manifest(self) -> dict:
        home = str(Path.home())
        return {
            "sources": [
                {
                    "path": str(p).replace(home, "~"),
                    "sha256": sha256_bytes(Path(p).read_bytes()),
                    "bytes": Path(p).stat().st_size,
                }
                for p in self.sources
            ]
        }

    def verify(self) -> bool:
        prev = GENESIS
        for row in self.rows:
            if row["prev_sha256"] != prev:
                return False
            if entry_hash(row) != row["entry_sha256"]:
                return False
            prev = row["entry_sha256"]
        return True


def write_bundle(events: list[dict], out_dir: Path, sources: list[Path]) -> dict:
    """events: normalized stream from ingest. Returns manifest dict."""
    out_dir.mkdir(parents=True, exist_ok=True)
    w = BundleWriter(sources)
    tss = [e.get("ts") for e in events if e.get("ts")]
    first_ts = min(tss) if tss else None
    last_ts = max(tss) if tss else None
    w.add("run_start", {
        "tool": "agent-forensics",
        "version": "0.1.0",
        "source_manifest": w.source_manifest(),
        "note": "forensic reconstruction; chain proves the reconstruction, "
                "not the originals",
    }, "forensics/run_start/1", ts=first_ts)
    counts = {}
    for ev in events:
        kind = ev["kind"]
        if kind == "tool_call":
            phase, rule = ev.get("phase"), ev.get("rule")
            payload = {
                "tool": ev.get("tool"),
                "command": ev.get("command"),
                "target": ev.get("target"),
                "phase": phase,
                "rule": rule,
                "sidechain": ev.get("sidechain"),
                "cwd": ev.get("cwd"),
            }
            w.add("tool_call", payload, "forensics/tool_call/1",
                  parent_seq=ev.get("parent"), ts=ev.get("ts"),
                  tool_call_id=ev.get("tool_call_id"))
        elif kind == "tool_result":
            w.add("tool_result", {
                "tool_use_id": ev.get("tool_use_id"),
                "result_sha256": ev.get("result_sha256"),
                "result_len": ev.get("result_len"),
            }, "forensics/tool_result/1", parent_seq=ev.get("parent"), ts=ev.get("ts"))
        elif kind == "approval":
            w.add("approval", {
                "tool": ev.get("tool"),
                "decision": ev.get("decision"),
                "scope": ev.get("scope"),
                "rule_sha256": ev.get("rule_sha256"),
            }, "forensics/approval/1", ts=ev.get("ts"),
                  tool_call_id=ev.get("tool_call_id"))
        elif kind == "user_prompt":
            w.add("prompt", {
                "prompt_sha256": ev.get("prompt_sha256"),
                "prompt_len": ev.get("prompt_len"),
            }, "forensics/prompt/1", parent_seq=ev.get("parent"), ts=ev.get("ts"))
        else:
            counts[kind] = counts.get(kind, 0) + 1
    if counts:
        w.add("observation", {"other_kinds": counts},
              "forensics/observation/1", ts=last_ts)
    w.add("run_end", {"rows": w.seq}, "forensics/run_end/1", ts=last_ts)

    assert w.verify(), "chain verification failed before write"
    transcript = out_dir / "transcript.jsonl"
    with open(transcript, "w", encoding="utf-8") as fh:
        for row in w.rows:
            fh.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    manifest = {
        "transcript_sha256": sha256_bytes(transcript.read_bytes()),
        "rows": len(w.rows),
        "sources": w.source_manifest()["sources"],
        "generated": _ts_now(),
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def verify_file(path: Path) -> bool:
    """Independently re-verify a written bundle from disk.

    Accepts genesis prev_sha256 of 64 zeros (agent-evidence-0.2 convention)
    or None (early forensic bundles); every later link must chain.
    """
    prev = None
    seen_first = False
    for line in open(path, encoding="utf-8"):
        row = json.loads(line)
        if not seen_first:
            if row["prev_sha256"] not in (None, GENESIS):
                return False
            seen_first = True
        elif row["prev_sha256"] != prev:
            return False
        if entry_hash(row) != row["entry_sha256"]:
            return False
        prev = row["entry_sha256"]
    return True
