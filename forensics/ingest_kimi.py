"""Ingest native Kimi Code wire.jsonl into the normalized event stream.

Source schema (observed 2026-09-02 from local sessions, structure only):
rows carry {type, time(epoch-ms)}; discriminators:
- metadata: cwd, created_at, protocol_version (session header)
- turn.prompt {input, origin}                     -> user prompt
- context.append_message {message{role, content}} -> injected/user message
- context.append_loop_event {event{type}}:
    tool.call    {name, args, toolCallId, uuid, turnId}      -> tool_call
    tool.result  {toolCallId, parentUuid, result}            -> tool_result
    content.part {part{text|think}}                          -> text/thinking
    step.begin / step.end                                    -> (counted)
- permission.record_approval_result {action, result{decision, scope},
  sessionApprovalRule, toolCallId, toolName}       -> approval ledger row
- turn.steer / turn.cancel                         -> human intervention
- llm.request / usage.record / config.update / tools.update_store /
  compaction rows                                  -> counted, not emitted

The approval ledger is the differentiating artifact: it records, per tool
call, whether a human approved it and with what scope. sessionApprovalRule
embeds the raw approved command, so it is hashed, never copied.

Deterministic: same file, same events, same order.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .canonical import payload_hash, sha256_text
from .phases import classify_command

_COUNTED_TYPES = {
    "llm.request", "usage.record", "config.update", "tools.update_store",
    "tools.set_active_tools", "llm.tools_snapshot",
    "full_compaction.begin", "full_compaction.complete",
    "context.apply_compaction",
}


def _iso(ms) -> str | None:
    if not isinstance(ms, (int, float)):
        return None
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _command_from_args(name: str, args) -> tuple[str, str | None]:
    """Return (command, target) from a tool.call args dict."""
    if not isinstance(args, dict):
        return "", None
    cmd = args.get("command")
    target = args.get("path") or args.get("file_path")
    return (str(cmd) if cmd else ""), (str(target) if target else None)


def ingest_file(path: Path) -> list[dict]:
    path = Path(path)
    session = None
    agent = None
    for part in path.parts:
        if part.startswith("session_"):
            session = part
        if part.startswith("agent-"):
            agent = part
    events: list[dict] = []
    seq = 0
    uuid_to_seq: dict[str, int] = {}
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
        ts = _iso(r.get("time"))
        base = {"seq_source": None, "ts": ts, "session": session,
                "cwd": cwd, "git_branch": None, "sidechain": False,
                "agent": agent}
        if rtype == "metadata":
            cwd = r.get("cwd") or cwd
            continue
        if rtype in _COUNTED_TYPES:
            continue
        if rtype == "turn.prompt":
            seq += 1
            events.append(dict(base, seq=seq, kind="user_prompt",
                               prompt_sha256=payload_hash(r.get("input")),
                               prompt_len=len(json.dumps(r.get("input"))) if r.get("input") else 0,
                               origin_kind=(r.get("origin") or {}).get("kind")))
        elif rtype == "context.append_message":
            message = r.get("message") or {}
            content = message.get("content")
            body = content if isinstance(content, str) else json.dumps(content)
            seq += 1
            events.append(dict(base, seq=seq, kind="user_prompt",
                               prompt_sha256=sha256_text(str(body or "")),
                               prompt_len=len(str(body or "")),
                               origin_kind=(message.get("origin") or {}).get("kind"),
                               injected=True))
        elif rtype == "turn.steer" or rtype == "turn.cancel":
            seq += 1
            events.append(dict(base, seq=seq, kind="control",
                               control=rtype.split(".")[1],
                               origin_kind=(r.get("origin") or {}).get("kind")))
        elif rtype == "permission.record_approval_result":
            result = r.get("result") or {}
            rule = r.get("sessionApprovalRule")
            seq += 1
            events.append(dict(base, seq=seq, kind="approval",
                               tool=r.get("toolName"),
                               tool_call_id=r.get("toolCallId"),
                               decision=result.get("decision"),
                               scope=result.get("scope"),
                               rule_sha256=sha256_text(str(rule)) if rule else None))
        elif rtype == "context.append_loop_event":
            ev = r.get("event") or {}
            etype = ev.get("type")
            if etype == "tool.call":
                name = str(ev.get("name") or "")
                cmd, target = _command_from_args(name, ev.get("args"))
                seq += 1
                hit = classify_command(cmd)
                events.append(dict(base, seq=seq, kind="tool_call",
                                   tool=name,
                                   tool_call_id=ev.get("toolCallId"),
                                   command=cmd,
                                   target=target,
                                   phase=hit[0] if hit else None,
                                   rule=hit[1] if hit else None))
                if ev.get("uuid"):
                    uuid_to_seq[ev["uuid"]] = seq
            elif etype == "tool.result":
                seq += 1
                result = ev.get("result")
                body = result if isinstance(result, str) else json.dumps(result)
                events.append(dict(base, seq=seq, kind="tool_result",
                                   tool_use_id=ev.get("toolCallId"),
                                   parent=uuid_to_seq.get(ev.get("parentUuid")),
                                   result_sha256=sha256_text(str(body or "")),
                                   result_len=len(str(body or ""))))
            elif etype == "content.part":
                part = ev.get("part") or {}
                ptype = part.get("type")
                if ptype in ("text", "think"):
                    seq += 1
                    body = str(part.get(ptype) or "")
                    events.append(dict(base, seq=seq,
                                       kind="assistant_text" if ptype == "text" else "assistant_thinking",
                                       text_sha256=sha256_text(body),
                                       text_len=len(body)))
        else:
            seq += 1
            events.append(dict(base, seq=seq, kind=f"native_{rtype or 'unknown'}"))
    return events
