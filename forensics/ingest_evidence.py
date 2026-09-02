"""Ingest an agent-evidence-0.2 transcript.jsonl (recorder output).

This is the reconstruction half meeting the capture half: bundles written
by the recorder (crashrange-live and the public sample) are the ground
truth of what a sealed run did. Rows use the same chain construction as
forensics/canonical.py; the chain is verified WHILE streaming and a
broken chain aborts ingestion (forensics on tampered evidence is refused,
not warned about).

Evidence rows hash value-bearing content (tool arguments, prompt text),
so classification here reconstructs STRUCTURE: which tools ran, when,
in what causal order, which control probes fired. Command-level phase
labels require native artifacts (claude/kimi ingests), not evidence rows.
"""
from __future__ import annotations

import json
from pathlib import Path

from .canonical import entry_hash

_COUNTED = {"heartbeat", "run_start", "run_end", "control_calibration",
            "recorder_close", "observation"}


class ChainBroken(Exception):
    """Raised when the source transcript's hash chain does not verify."""


def ingest_file(path: Path) -> list[dict]:
    events: list[dict] = []
    seq = 0
    prev = None
    seen_first = False
    for line in open(path, encoding="utf-8", errors="replace"):
        try:
            row = json.loads(line)
        except Exception:
            raise ChainBroken(f"unparseable row after {seq} rows")
        if not isinstance(row, dict) or "entry_sha256" not in row:
            raise ChainBroken(f"row {seq} is not an evidence row")
        if entry_hash(row) != row["entry_sha256"]:
            raise ChainBroken(f"row {seq} entry_sha256 mismatch")
        if not seen_first:
            if row.get("prev_sha256") not in (None, "0" * 64):
                raise ChainBroken("bad genesis prev_sha256")
            seen_first = True
        elif row.get("prev_sha256") != prev:
            raise ChainBroken(f"row {seq} prev_sha256 link broken")
        prev = row["entry_sha256"]

        rtype = row.get("type")
        payload = row.get("payload") or {}
        base = {"seq_source": None, "ts": row.get("ts"), "session": None,
                "cwd": None, "git_branch": None, "sidechain": False,
                "agent": None}
        if rtype == "prompt":
            seq += 1
            events.append(dict(base, seq=seq, kind="user_prompt",
                               prompt_sha256=payload.get("content_sha256"),
                               prompt_len=None,
                               origin_kind=payload.get("source")))
        elif rtype == "tool_call":
            args = payload.get("arguments") or {}
            seq += 1
            events.append(dict(base, seq=seq, kind="tool_call",
                               tool=payload.get("tool"),
                               tool_call_id=row.get("tool_call_id"),
                               command="",
                               arg_sha256=args.get("sha256"),
                               arg_bytes=args.get("bytes"),
                               phase=None, rule=None,
                               evidence=True))
        elif rtype == "tool_result":
            seq += 1
            events.append(dict(base, seq=seq, kind="tool_result",
                               tool_use_id=row.get("tool_call_id"),
                               parent=row.get("parent_seq"),
                               result_sha256=payload.get("sha256")
                               or payload.get("output_sha256"),
                               result_len=payload.get("bytes")))
        elif rtype == "control_probe":
            seq += 1
            events.append(dict(base, seq=seq, kind="control",
                               control="probe",
                               probe=payload.get("probe") or payload.get("sensor")))
        elif rtype in _COUNTED:
            continue
        else:
            seq += 1
            events.append(dict(base, seq=seq, kind=f"native_{rtype or 'unknown'}"))
    return events
