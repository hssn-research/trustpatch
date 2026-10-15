from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__

GENESIS_HASH = "0" * 64


def digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(payload).hexdigest()


def _log_path(directory: Path) -> Path:
    return directory / "audit.jsonl"


def _last_hash(directory: Path) -> str:
    log = _log_path(directory)
    if not log.exists():
        return GENESIS_HASH
    last_line = None
    with log.open() as handle:
        for line in handle:
            line = line.strip()
            if line:
                last_line = line
    if last_line is None:
        return GENESIS_HASH
    return json.loads(last_line)["record_hash"]


def append_event(directory: Path, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Append a tamper-evident audit event. Each record hashes the previous record's
    hash, so any deletion/reordering/edit of prior lines is detectable by verify_chain.
    This is hash-chaining for tamper *evidence*, not a cryptographic signature — a
    production deployment should additionally sign records with an offline key."""
    directory.mkdir(parents=True, exist_ok=True)
    previous_hash = _last_hash(directory)
    event = {
        "event_id": "evt_" + uuid.uuid4().hex,
        "timestamp": datetime.now(UTC).isoformat(),
        "agent_version": __version__,
        "operation": operation,
        "evidence_digest": digest(payload),
        "previous_hash": previous_hash,
        "payload": payload,
    }
    event["record_hash"] = digest(event)
    with _log_path(directory).open("a") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
    return event


@dataclass
class ChainVerification:
    valid: bool
    event_count: int
    broken_at: str | None = None
    reason: str | None = None


def verify_chain(directory: Path) -> ChainVerification:
    """Independently recompute the hash chain. Returns valid=False on the first
    event whose stored record_hash or previous_hash link does not match."""
    log = _log_path(directory)
    if not log.exists():
        return ChainVerification(valid=True, event_count=0)
    expected_previous = GENESIS_HASH
    count = 0
    with log.open() as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            count += 1
            if record.get("previous_hash") != expected_previous:
                return ChainVerification(False, count, record.get("event_id"), "previous_hash mismatch")
            stored_hash = record.get("record_hash")
            recomputed = digest({k: v for k, v in record.items() if k != "record_hash"})
            if stored_hash != recomputed:
                return ChainVerification(False, count, record.get("event_id"), "record_hash mismatch")
            expected_previous = stored_hash
    return ChainVerification(True, count)
