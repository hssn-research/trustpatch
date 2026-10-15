from __future__ import annotations
import hashlib, json, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

def digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(payload).hexdigest()

def append_event(directory: Path, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    event = {"event_id": "evt_" + uuid.uuid4().hex, "timestamp": datetime.now(timezone.utc).isoformat(), "agent_version": "0.1.0", "operation": operation, "evidence_digest": digest(payload), "payload": payload}
    with (directory / "audit.jsonl").open("a") as handle: handle.write(json.dumps(event, sort_keys=True) + "\n")
    return event
