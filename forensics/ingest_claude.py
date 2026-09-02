"""Ingest native Claude Code session JSONL into a normalized event stream.

Source schema (observed 2026-09-02 from local sessions, structure only):
entries carry type (user|assistant|attachment|...), message (Anthropic
content blocks), toolUseResult, timestamp, sessionId, parentUuid (causal
chain), cwd, gitBranch, entrypoint, isSidechain, uuid, version.

Output events: dicts with kind, ts, seq (arrival), parent (causal parent
event id or None), and kind-specific fields. No file contents are copied
beyond what classification needs: command strings and tool names are kept
(value-bearing evidence), file paths are kept, message text bodies are
truncated hashes by default (forensics never re-emit prose it was not
asked to re-emit).

Deterministic: same file, same events, same order.
"""
from __future__ import annotations

import json
from pathlib import Path

from .canonical import sha256_text
from .phases import classify_command


def _blocks(message):
    content = (message or {}).get("content")
    if isinstance(content, str):
        yield {"type": "text", "text": content}
    elif isinstance(content, list):
        for b in content:
            if isinstance(b, dict):
                yield b


def _command_from_tool(name: str, inp: dict) -> str:
    """Best-effort single command string from a tool call input."""
    if not isinstance(inp, dict):
        return ""
    if name in ("Bash", "bash") or "command" in inp and name.lower() in ("run", "shell"):
        return str(inp.get("command") or "")
    for k in ("command", "script", "cmd"):
        if k in inp:
            return str(inp[k])
    return ""


def ingest_file(path: Path) -> list[dict]:
    events = []
    seq = 0
    uuid_to_event = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                e = json.loads(line)
            except Exception:
                seq += 1
                events.append({"kind": "unparseable", "seq": seq,
                               "parent": None, "raw_sha256": sha256_text(line.rstrip("\n"))})
                continue
            if not isinstance(e, dict):
                continue
            ts = e.get("timestamp")
            parent = e.get("parentUuid")
            base = {
                "seq_source": e.get("uuid"),
                "ts": ts,
                "parent": uuid_to_event.get(parent) if parent else None,
                "session": e.get("sessionId"),
                "cwd": e.get("cwd"),
                "git_branch": e.get("gitBranch"),
                "sidechain": bool(e.get("isSidechain")),
            }
            etype = e.get("type")
            if etype == "assistant":
                message = e.get("message") or {}
                for b in _blocks(message):
                    btype = b.get("type")
                    seq += 1
                    ev = dict(base, seq=seq)
                    if btype == "tool_use":
                        name = str(b.get("name") or "")
                        inp = b.get("input") or {}
                        cmd = _command_from_tool(name, inp)
                        target = (inp.get("file_path") or inp.get("path")
                                  or inp.get("notebook_path")) if isinstance(inp, dict) else None
                        ev.update({
                            "kind": "tool_call",
                            "tool": name,
                            "tool_call_id": b.get("id"),
                            "command": cmd,
                            "target": str(target) if target else None,
                            "input_keys": sorted(inp.keys()) if isinstance(inp, dict) else [],
                            "phase": None,
                            "rule": None,
                        })
                        hit = classify_command(cmd)
                        if hit:
                            ev["phase"], ev["rule"] = hit
                        uuid_to_event[e.get("uuid")] = seq
                    elif btype == "text":
                        ev.update({
                            "kind": "assistant_text",
                            "text_sha256": sha256_text(str(b.get("text") or "")),
                            "text_len": len(str(b.get("text") or "")),
                        })
                    else:
                        ev.update({"kind": f"assistant_{btype or 'block'}"})
                    events.append(ev)
            elif etype == "user":
                message = e.get("message") or {}
                tool_results = [b for b in _blocks(message) if b.get("type") == "tool_result"]
                if tool_results:
                    for b in tool_results:
                        seq += 1
                        content = b.get("content")
                        body = content if isinstance(content, str) else json.dumps(content)
                        events.append(dict(base, seq=seq, kind="tool_result",
                                           tool_use_id=b.get("tool_use_id"),
                                           result_sha256=sha256_text(str(body or "")),
                                           result_len=len(str(body or ""))))
                else:
                    seq += 1
                    events.append(dict(base, seq=seq, kind="user_prompt",
                                       prompt_sha256=sha256_text(str(message.get("content") or "")),
                                       prompt_len=len(str(message.get("content") or ""))))
                uuid_to_event[e.get("uuid")] = seq
            elif etype == "attachment":
                seq += 1
                events.append(dict(base, seq=seq, kind="attachment"))
            else:
                seq += 1
                events.append(dict(base, seq=seq, kind=f"native_{etype or 'unknown'}"))
                uuid_to_event[e.get("uuid")] = seq
    return events
