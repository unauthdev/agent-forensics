"""Ingest a saved cursor-agent stream-json transcript.

Source: `cursor-agent -p --output-format stream-json ... | tee run.jsonl`
(one JSON object per line). Row types observed 2026-09-05 from live
no-op + read-only probes in an empty workspace, structure only:
- system {cwd, session_id, model, permissionMode}   -> session header
- user {message{role, content}}                      -> user prompt
- thinking {text}                                    -> assistant thinking
- assistant {message{role, content}}                  -> assistant text
- tool_call {subtype started|completed, call_id, tool_call{<name>ToolCall,
  toolCallId, startedAtMs, completedAtMs}, session_id, timestamp_ms}
  -> tool_call (+ tool_result on completion)
- result {subtype, is_error, usage}                  -> counted, not emitted

Tool payloads: the tool_call dict holds exactly one <name>ToolCall key
(shellToolCall, readToolCall, globToolCall observed; write/edit handled
generically). shell args carry `command`; file tools carry `path`
(or file_path); globs carry `globPattern` (a read-shaped target).

Output events match the normalized stream (same keys as ingest_kimi):
prose is hashed, never copied; commands and paths are kept as evidence.
Approvals are not present in this transcript shape (ask-mode probes
auto-run); approval rows are a known gap, not silently filled.

Deterministic: same file, same events, same order.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .canonical import sha256_text
from .phases import classify_command

_COUNTED_SUBTYPES = {"success"}  # result-row subtypes: counted, not emitted


def _iso(ms) -> str | None:
    if not isinstance(ms, (int, float)):
        return None
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _blocks(message):
    content = (message or {}).get("content")
    if isinstance(content, str):
        yield {"type": "text", "text": content}
    elif isinstance(content, list):
        for b in content:
            if isinstance(b, dict):
                yield b


def _tool_name_and_args(tc: dict) -> tuple[str, dict]:
    """The <name>ToolCall entry: ('shell', args). Unknown shape ok."""
    if not isinstance(tc, dict):
        return "", {}
    for key, val in tc.items():
        if key.endswith("ToolCall") and isinstance(val, dict):
            name = key[: -len("ToolCall")]
            args = val.get("args")
            return name, args if isinstance(args, dict) else {}
    return "", {}


def _command_from_args(args: dict) -> str:
    for key in ("command", "script", "cmd"):
        if args.get(key):
            return str(args[key])
    return ""


def _target_from_args(args: dict) -> str | None:
    for key in ("path", "file_path", "file", "notebook_path", "globPattern"):
        if args.get(key):
            return str(args[key])
    return None


def ingest_file(path: Path) -> list[dict]:
    events: list[dict] = []
    seq = 0
    seen_calls: set[str] = set()
    session = None
    cwd = None
    for line in open(path, encoding="utf-8", errors="replace"):
        try:
            r = json.loads(line)
        except Exception:
            seq += 1
            events.append({"kind": "unparseable", "seq": seq, "parent": None,
                           "raw_sha256": sha256_text(line.rstrip("\n"))})
            continue
        if not isinstance(r, dict):
            continue
        rtype = r.get("type")
        ts = _iso(r.get("timestamp_ms"))
        if rtype == "system":
            session = r.get("session_id") or session
            cwd = r.get("cwd") or cwd
            continue
        base = {"seq_source": None, "ts": ts, "session": session,
                "cwd": cwd, "git_branch": None, "sidechain": False}
        if rtype == "user":
            seq += 1
            body = json.dumps(r.get("message"))
            events.append(dict(base, seq=seq, kind="user_prompt",
                               prompt_sha256=sha256_text(body),
                               prompt_len=len(body)))
        elif rtype == "thinking":
            seq += 1
            body = str(r.get("text") or "")
            events.append(dict(base, seq=seq, kind="assistant_thinking",
                               text_sha256=sha256_text(body),
                               text_len=len(body)))
        elif rtype == "assistant":
            for b in _blocks(r.get("message")):
                if b.get("type") != "text":
                    continue
                seq += 1
                body = str(b.get("text") or "")
                events.append(dict(base, seq=seq, kind="assistant_text",
                                   text_sha256=sha256_text(body),
                                   text_len=len(body)))
        elif rtype == "tool_call":
            tc = r.get("tool_call") or {}
            call_id = str(tc.get("toolCallId") or r.get("call_id") or "")
            name, args = _tool_name_and_args(tc)
            cmd = _command_from_args(args)
            target = _target_from_args(args)
            call_cwd = args.get("workingDirectory") or cwd
            if call_id not in seen_calls:
                seen_calls.add(call_id)
                seq += 1
                hit = classify_command(cmd)
                events.append(dict(base, seq=seq, kind="tool_call",
                                   tool=name or "cursor",
                                   tool_call_id=call_id,
                                   command=cmd, target=target, cwd=call_cwd,
                                   phase=hit[0] if hit else None,
                                   rule=hit[1] if hit else None))
            if tc.get("completedAtMs") is not None or (
                    args.get("result") is not None
                    if isinstance(args, dict) else False):
                inner = (args.get("result") if isinstance(args, dict)
                         else None)
                body = json.dumps(inner, sort_keys=True)
                seq += 1
                events.append(dict(base, seq=seq, kind="tool_result",
                                   tool_use_id=call_id,
                                   result_sha256=sha256_text(body),
                                   result_len=len(body)))
        elif rtype == "result":
            continue  # run summary (usage, error flag): counted, not emitted
        else:
            seq += 1
            events.append(dict(base, seq=seq, kind=f"native_{rtype or 'unknown'}"))
    return events
