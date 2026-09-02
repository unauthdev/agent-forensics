# agent-forensics

Reconstruct what an AI agent did on a machine, after the fact, from the
artifacts it left on disk. Deterministic, offline, no model calls.

## The problem

In July 2026 a frontier AI lab published an intrusion postmortem: a
compromised repo led to agent sessions running recon, credential theft,
payload staging, and exfiltration, roughly 17,600 recovered actions
across nine attack phases. The raw logs were gone with the pods, and the
public reconstruction ends where the artifacts end.

Most agent installs are not ephemeral. Claude Code and Kimi Code both
write full session logs as JSONL under your home directory: every prompt,
every tool call, every result, with timestamps and causal links. When
someone asks "what did the agent actually do on this box", the answer is
already on disk. Nothing in the standard IR toolkit reads those files.
This does.

## What it does

- Ingests native session logs: Claude Code session JSONL, Kimi Code
  wire.jsonl (including its approval ledger and steer/cancel records),
  and agent-evidence-0.2 transcript bundles (chain-verified while
  streaming; a broken chain aborts ingestion).
- Classifies every tool call against a published incident taxonomy
  (recon, credential-access, evasion, exfil, dropper, c2, k8s,
  supply-chain, pivot). Deterministic regex rules. Every match records
  the rule id that fired.
- Flags boundary crossings: network egress, credential-artifact touches,
  reads and writes outside the session working directory.
- Emits a tamper-evident hash-chained transcript (each row's sha256
  commits to the previous row) plus a one-page human timeline.
- Indexes every local session into one chained ledger (aggregates only:
  counts, hashes, time ranges).
- Renders the session as a Mermaid causal graph (graph.md): nodes are
  events, edges follow the observed causal chain, phases are colored,
  boundary crossings are marked, approvals and human interventions are
  linked to the calls they govern. Renders natively on GitHub.

## Quickstart

    python3 -m forensics ~/.claude/projects/<project-dir>/<session>.jsonl --out /tmp/recon
    cat /tmp/recon/timeline.md
    cat /tmp/recon/graph.md

Synthetic demo, no real data required:

    python3 -m forensics forensics/fixtures/synthetic-incident-claude.jsonl forensics/fixtures/synthetic-incident-kimi.jsonl --out /tmp/demo

Verify a bundle chain independently:

    python3 -c "from pathlib import Path; from forensics.bundle import verify_file; print(verify_file(Path('forensics/fixtures/demo-bundle/transcript.jsonl')))"

Index every local session (both formats, autodetected) into one chained
ledger of aggregates:

    python3 -m forensics --ledger-out /tmp/ledger

Tests (stdlib only; pytest for the suite):

    python3 -m pip install pytest
    python3 -m pytest tests/ -q

## Honesty rules

- Labels are classifications, not accusations. A command labeled recon
  means it matched rule recon/proc-net-env. Nothing more.
- Prompts and assistant text are hashed, never re-emitted. Commands and
  file paths are kept: they are the evidence.
- The chain proves the integrity of the reconstruction, not of the
  originals. The source manifest sha256s the original input files.
- Evidence-bundle ingest reconstructs structure only: upstream recorders
  hash tool arguments, so phase labels require native session logs.

## Limits

- Two native formats today (Claude Code, Kimi Code) plus evidence
  transcripts. Adapters are one file each; PRs welcome.
- If the artifacts are gone (ephemeral pods, wiped runners), there is
  nothing to read. Collect before teardown.

## Success criteria (pre-registered)

This project publishes its own bar before promotion. Within 14 days of
the first public post, GO requires any one of: 25 or more stars, a
citation or share from an account with a real incident-response
audience, or an issue or message from a practitioner who ran it on their
own artifacts. Otherwise the project is parked, not promoted. Written
2026-09-02, before the clock started.

## Contact

security@unauth.dev

MIT license. Copyright (c) 2026 unauth.dev.
