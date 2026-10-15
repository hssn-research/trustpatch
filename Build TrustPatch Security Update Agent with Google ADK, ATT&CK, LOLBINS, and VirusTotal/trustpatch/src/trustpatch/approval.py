from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass
class Approval:
    update_id: str
    decision: str
    actor: str
    reason: str
    timestamp: str
    evidence_digest: str
    expires_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _path(control_dir: Path, update_id: str) -> Path:
    return control_dir / "approvals" / f"{update_id}.json"


def record(
    control_dir: Path,
    update_id: str,
    decision: str,
    actor: str,
    reason: str,
    evidence_digest: str,
    expires_at: str | None = None,
) -> Approval:
    """Store an explicit human decision bound to the exact evidence digest reviewed.
    A later, different digest (a changed proposal or a re-run verification) makes
    this record fail is_valid() automatically — approval never survives drift
    (FR-013 Exact Approval Binding)."""
    approval = Approval(update_id, decision, actor, reason, datetime.now(UTC).isoformat(), evidence_digest, expires_at)
    path = _path(control_dir, update_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(approval.to_dict(), indent=2))
    return approval


def load(control_dir: Path, update_id: str) -> Approval | None:
    path = _path(control_dir, update_id)
    if not path.exists():
        return None
    return Approval(**json.loads(path.read_text()))


def is_valid(approval: Approval | None, expected_digest: str, now: datetime | None = None) -> tuple[bool, str]:
    if approval is None:
        return False, "no approval recorded"
    if approval.decision != "approved":
        return False, f"recorded decision is {approval.decision!r}, not approved"
    if approval.evidence_digest != expected_digest:
        return False, "approval evidence digest does not match the current proposal/verification state"
    if approval.expires_at:
        now = now or datetime.now(UTC)
        if now > datetime.fromisoformat(approval.expires_at):
            return False, "approval has expired"
    return True, "ok"
