"""Ingest Factory Droid session JSONL into a normalized event stream.

Source schema (observed 2026-09-05 from local sessions, structure only):
one JSON object per line, `<uuid>.jsonl` under ~/.factory/sessions/<slug>/:
- session_start {id, title, cwd, ...}  -> session header (no event)
- message {id, timestamp, message{role, content}} -> prompts, tool calls,
  results, thinking, text (content blocks mirror the Anthropic shape:
  tool_use {id, name, input}, tool_result {tool_use_id, content})
- agent_turn_outcome / compaction_state / todo_state -> counted, not emitted

Tool names observed: Execute (input.command), Read/Edit (input paths),
plus ToolSearch/FetchUrl/WebSearch/LS/Grep/TodoWrite/AskUser. Command and
target extraction is generic (command/script/cmd; file_path/path), so
unseen tools degrade to command-less/target-less calls, never to silence.

Output events match the normalized stream (same keys as ingest_claude):
prose is hashed, never copied; commands and paths are kept as evidence.
No causal parent linkage exists in this shape (parent is always None).

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
    if not isinstance(inp, dict):
        return ""
    if name == "Execute" or "command" in inp and name.lower() in ("run", "shell"):
        return str(inp.get("command") or "")
    for key in ("command", "script", "cmd"):
        if key in inp:
            return str(inp[key])
    return ""


def _target_from_input(inp: dict) -> str | None:
    if not isinstance(inp, dict):
        return None
    for key in ("file_path", "path", "notebook_path", "file"):
        if inp.get(key):
            return str(inp[key])
    return None


def ingest_file(path: Path) -> list[dict]:
    events = []
    seq = 0
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
        if rtype == "session_start":
            session = r.get("id") or session
            cwd = r.get("cwd") or cwd
            continue
        if rtype != "message":
            seq += 1
            events.append({"kind": f"native_{rtype or 'unknown'}", "seq": seq,
                           "parent": None, "session": session, "cwd": cwd,
                           "ts": r.get("timestamp")})
            continue
        message = r.get("message") or {}
        role = message.get("role")
        ts = r.get("timestamp")
        base = {"ts": ts, "parent": None, "session": session, "cwd": cwd,
                "git_branch": None, "sidechain": False}
        if role == "user":
            blocks = list(_blocks(message))
            results = [b for b in blocks if b.get("type") == "tool_result"]
            if results:
                for b in results:
                    seq += 1
                    content = b.get("content")
                    body = (content if isinstance(content, str)
                            else json.dumps(content))
                    events.append(dict(base, seq=seq, kind="tool_result",
                                       tool_use_id=b.get("tool_use_id"),
                                       result_sha256=sha256_text(str(body or "")),
                                       result_len=len(str(body or ""))))
            else:
                seq += 1
                body = json.dumps(message.get("content"))
                events.append(dict(base, seq=seq, kind="user_prompt",
                                   prompt_sha256=sha256_text(body),
                                   prompt_len=len(body)))
        elif role == "assistant":
            for b in _blocks(message):
                btype = b.get("type")
                seq += 1
                if btype == "tool_use":
                    name = str(b.get("name") or "")
                    inp = b.get("input") or {}
                    cmd = _command_from_tool(name, inp)
                    ev = dict(base, seq=seq, kind="tool_call",
                              tool=name, tool_call_id=b.get("id"),
                              command=cmd, target=_target_from_input(inp),
                              input_keys=(sorted(inp.keys())
                                          if isinstance(inp, dict) else []),
                              phase=None, rule=None)
                    hit = classify_command(cmd)
                    if hit:
                        ev["phase"], ev["rule"] = hit
                    events.append(ev)
                elif btype == "text":
                    events.append(dict(base, seq=seq, kind="assistant_text",
                                       text_sha256=sha256_text(str(b.get("text") or "")),
                                       text_len=len(str(b.get("text") or ""))))
                elif btype == "thinking":
                    events.append(dict(base, seq=seq, kind="assistant_thinking",
                                       text_sha256=sha256_text(json.dumps(b.get("thinking"))),
                                       text_len=len(json.dumps(b.get("thinking")))))
                else:
                    events.append(dict(base, seq=seq,
                                       kind=f"assistant_{btype or 'block'}"))
        else:
            seq += 1
            events.append(dict(base, seq=seq,
                               kind=f"native_message_{role or 'unknown'}"))
    return events
