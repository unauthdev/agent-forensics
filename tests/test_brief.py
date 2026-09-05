"""Session brief (--last/--brief): democratized receipt. Deterministic only."""

import json

from forensics.brief import find_latest, render_brief


def _xev(seq, kind="tool_call", **kw):
    e = {"seq": seq, "kind": kind, "ts": f"2026-07-15T09:{seq // 60:02d}:{seq % 60:02d}Z",
         "tool": "Bash", "session": "s", "cwd": "/w"}
    e.update(kw)
    return e


def _events():
    return [
        _xev(1, kind="user_prompt", prompt_sha256="ab"),
        _xev(2, tool="Edit", command="", target="/w/app.py"),
        _xev(3, command="cat ~/.aws/credentials", phase="credential-access",
             rule="cred/agent-artifact"),
        _xev(4, command="curl -s https://api.invalid/health"),
    ]


def test_find_latest_picks_newest(tmp_path):
    import os
    import time
    claude = tmp_path / "projects"
    proj = claude / "-proj"
    proj.mkdir(parents=True)
    old = proj / "old.jsonl"
    old.write_text('{"type":"user"}\n')
    time.sleep(0.01)
    new = proj / "new.jsonl"
    new.write_text('{"type":"user"}\n')
    os.utime(new, (new.stat().st_atime + 5, new.stat().st_mtime + 5))
    kimi = tmp_path / "sessions"
    kimi.mkdir()
    found = find_latest(claude, kimi)
    assert found is not None and found[0] == new and found[1] == "claude"


def test_find_latest_empty_is_none(tmp_path):
    assert find_latest(tmp_path / "nope-c", tmp_path / "nope-k",
                       tmp_path / "nope-d") is None


def test_render_brief_sections(tmp_path):
    src = tmp_path / "s.jsonl"
    src.write_text('{"type":"user"}\n')
    text = render_brief(_events(), [src], "claude", True)
    assert "# Session brief" in text
    assert "## Built (1 files)" in text
    assert "/w/app.py" in text
    assert "## Ran (" in text
    assert "## Crossed a boundary" in text
    assert "credential-artifact" in text
    assert "## Worth a look" in text
    assert "classifications, not accusations" in text


def test_render_brief_quiet_session(tmp_path):
    src = tmp_path / "s.jsonl"
    src.write_text('{"type":"user"}\n')
    events = [_xev(1, kind="user_prompt"), _xev(2, command="ls -la")]
    text = render_brief(events, [src], "claude", True)
    assert "Quiet session" in text
    assert "No file targets" in text


def test_cli_brief_writes_brief_md(tmp_path):
    rows = [
        {"type": "user", "uuid": "u1", "parentUuid": None, "sessionId": "s1",
         "timestamp": "2026-09-02T10:00:00.000Z", "cwd": "/w",
         "message": {"content": "do it"}},
        {"type": "assistant", "uuid": "a1", "parentUuid": "u1", "sessionId": "s1",
         "timestamp": "2026-09-02T10:00:05.000Z", "cwd": "/w",
         "message": {"content": [
             {"type": "tool_use", "id": "t1", "name": "Bash",
              "input": {"command": "ls -la"}},
         ]}},
    ]
    src = tmp_path / "session.jsonl"
    src.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    out = tmp_path / "bundle"
    from forensics.__main__ import main
    assert main([str(src), "--out", str(out), "--brief"]) == 0
    brief = (out / "brief.md").read_text()
    assert "# Session brief" in brief
    assert "chain OK" in brief


def test_cli_last_resolves_newest(tmp_path, capsys):
    import os
    import time
    claude = tmp_path / "projects"
    proj = claude / "-proj"
    proj.mkdir(parents=True)
    rows = "\n".join(json.dumps({
        "type": "user", "uuid": "u1", "parentUuid": None, "sessionId": "s1",
        "timestamp": "2026-09-02T10:00:00.000Z", "cwd": "/w",
        "message": {"content": "do it"}}) for _ in range(1)) + "\n"
    a = proj / "a.jsonl"
    a.write_text(rows)
    time.sleep(0.01)
    b = proj / "b.jsonl"
    b.write_text(rows)
    os.utime(b, (b.stat().st_atime + 5, b.stat().st_mtime + 5))
    from forensics.__main__ import main
    assert main(["--last", "--brief", "--claude-root", str(claude),
                 "--kimi-root", str(tmp_path / "nosuch"),
                 "--droid-root", str(tmp_path / "nosuch")]) == 0
    out = capsys.readouterr().out
    assert "b.jsonl" in out and "# Session brief" in out
