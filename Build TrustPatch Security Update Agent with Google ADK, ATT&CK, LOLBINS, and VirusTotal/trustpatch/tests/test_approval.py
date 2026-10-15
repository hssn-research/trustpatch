from datetime import UTC, datetime, timedelta

from trustpatch import approval


def test_approval_is_valid_when_digest_matches(tmp_path):
    record = approval.record(tmp_path, "u1", "approved", "alice", "fix cve", "digest-1")
    ok, why = approval.is_valid(record, "digest-1")
    assert ok is True, why


def test_approval_invalid_when_digest_drifted(tmp_path):
    record = approval.record(tmp_path, "u1", "approved", "alice", "fix cve", "digest-1")
    ok, why = approval.is_valid(record, "digest-2")
    assert ok is False
    assert "digest" in why


def test_approval_invalid_when_rejected(tmp_path):
    record = approval.record(tmp_path, "u1", "rejected", "alice", "too risky", "digest-1")
    ok, _ = approval.is_valid(record, "digest-1")
    assert ok is False


def test_approval_expires(tmp_path):
    expires_at = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    record = approval.record(tmp_path, "u1", "approved", "alice", "fix cve", "digest-1", expires_at)
    ok, why = approval.is_valid(record, "digest-1")
    assert ok is False
    assert "expired" in why


def test_no_approval_recorded():
    ok, why = approval.is_valid(None, "digest-1")
    assert ok is False
    assert "no approval" in why
