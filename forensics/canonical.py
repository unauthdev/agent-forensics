"""Canonical hashing, matched to the public evidence-sample construction.

Derived 2026-09-02 against content/public-sample/known-bad (row seq=1):
entry_sha256 = sha256 of the row minus entry_sha256, json.dumps with
sort_keys=True and compact separators. payload_sha256 same over payload.
"""
from __future__ import annotations

import hashlib
import json


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def payload_hash(payload) -> str:
    return sha256_text(canonical_json(payload))


def entry_hash(row: dict) -> str:
    stripped = {k: v for k, v in row.items() if k != "entry_sha256"}
    return sha256_text(canonical_json(stripped))
