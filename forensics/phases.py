"""Deterministic phase classification over reconstructed tool calls.

Taxonomy follows the published Hugging Face July 2026 incident timeline
(recon, rce, dropper, exfil, c2, evasion, k8s, supply-chain, pivot,
credential-access). Every match records the rule id that fired. A label
is a classification, not an accusation; the timeline says "matched rule".

Order matters: first rule that matches wins, most specific first.
"""
from __future__ import annotations

import re

RULES = [
    ("evasion", "evasion/gzip-b64-exec",
     re.compile(r"gzip\.decompress|base64\.b64decode|zlib\.decompress", re.I)),
    ("evasion", "evasion/packing-imports",
     re.compile(r"import\s+[^#\n]*\b(gzip|zlib|base64)\b\s*,")),
    ("credential-access", "cred/k8s-serviceaccount",
     re.compile(r"/var/run/secrets/kubernetes\.io/serviceaccount", re.I)),
    ("credential-access", "cred/cloud-metadata",
     re.compile(r"169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data", re.I)),
    ("credential-access", "cred/agent-artifact",
     re.compile(r"\.claude/\.credentials|\.codex/auth\.json|\.kimi-code/credentials|"
                r"\.aws/credentials|\.npmrc|\.docker/config\.json|kube?config|"
                r"id_rsa|\.netrc|credentials\.json", re.I)),
    ("k8s", "k8s/api-or-kubectl",
     re.compile(r"\bkubectl\b|kubernetes\.default\.svc|\.eks\.amazonaws\.com|"
                r"serviceaccount/(token|namespace|ca\.crt)", re.I)),
    ("supply-chain", "supply-chain/git-token-clone",
     re.compile(r"git clone\s+https?://[^\s]*@|x-access-token:|ghp_[A-Za-z0-9]|"
                r"github.*installation[_ ]token|npm publish|twine upload", re.I)),
    ("pivot", "pivot/mesh-vpn",
     re.compile(r"\btailscaled?\b|--auth-key|tailscale\.com|wireguard|zerotier", re.I)),
    ("c2", "c2/staged-exec",
     re.compile(r"python3?\s+/tmp/|curl[^|;&]*\|\s*(ba)?sh|wget[^|;&]*\|\s*(ba)?sh|"
                r"/dev/tcp/|nohup\s+.*&", re.I)),
    ("exfil", "exfil/outbound-post",
     re.compile(r"(curl|wget|nc|ncat|socat)[^;&|]*(\s-d\s|\s--data[^ ]*\s|\s-X\s*POST|"
                r"\s--post[^ ]*\s).*https?://|socket\.create_connection|requests\.post", re.I)),
    ("dropper", "dropper/stage-download",
     re.compile(r"(curl|wget)[^;&|]*-o\s+\S+|base64\s+-d\s*>|chmod\s+\+x\s+/tmp/", re.I)),
    ("recon", "recon/proc-net-env",
     re.compile(r"/proc/self/(mountinfo|environ|status)|/etc/passwd|\bifconfig\b|\bip addr\b|"
                r"env$|\benv\b(?=\s*;|$)|getent hosts|cat\s+~/.ssh", re.I)),
]


# One-fact-one-place: what firing this rule actually observed, in plain
# language. Rendered verbatim in the timeline's "What the labels mean"
# and in each "Read this first" entry. Describes the match, never an actor.
RULE_HELP = {
    "evasion/gzip-b64-exec":
        "decompresses or decodes gzip/zlib/base64 data in Python, the "
        "common way hidden payloads are unpacked",
    "evasion/packing-imports":
        "imports gzip/zlib/base64 libraries, the usual precursor to "
        "unpacking obfuscated data",
    "cred/k8s-serviceaccount":
        "references the Kubernetes service-account mount, where a pod's "
        "credentials live",
    "cred/cloud-metadata":
        "targets a cloud metadata endpoint, where instance credentials live",
    "cred/agent-artifact":
        "names a credential file (cloud keys, SSH keys, agent auth, "
        "kubeconfig, .netrc)",
    "k8s/api-or-kubectl":
        "uses kubectl or the in-cluster Kubernetes API",
    "supply-chain/git-token-clone":
        "clones with an embedded token or runs a package publish "
        "(npm/twine)",
    "pivot/mesh-vpn":
        "installs or uses mesh-VPN tooling (tailscale, wireguard, zerotier)",
    "c2/staged-exec":
        "executes downloaded or staged code (curl|sh, /tmp execution, "
        "nohup backgrounding, /dev/tcp)",
    "exfil/outbound-post":
        "sends data to an external URL (POST, --data, raw socket)",
    "dropper/stage-download":
        "downloads to a file or makes a staged file executable",
    "recon/proc-net-env":
        "reads process, environment, or network internals (/proc, "
        "/etc/passwd, env, ssh files, interfaces)",
}


def rule_help(rule_id: str) -> str:
    return RULE_HELP.get(rule_id, "matched a classification pattern")


def classify_command(command: str) -> tuple[str, str] | None:
    """Return (phase, rule_id) for the first matching rule, else None."""
    if not command:
        return None
    for phase, rule_id, pat in RULES:
        if pat.search(command):
            return phase, rule_id
    return None


def phase_order():
    return [p for p, _, _ in RULES]
