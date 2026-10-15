import json

from trustpatch.audit import append_event, verify_chain


def test_chain_is_valid_after_several_events(tmp_path):
    for i in range(3):
        append_event(tmp_path, "op", {"i": i})
    result = verify_chain(tmp_path)
    assert result.valid is True
    assert result.event_count == 3


def test_chain_detects_tampering(tmp_path):
    append_event(tmp_path, "op", {"i": 0})
    append_event(tmp_path, "op", {"i": 1})
    log = tmp_path / "audit.jsonl"
    lines = log.read_text().splitlines()
    record = json.loads(lines[0])
    record["payload"]["i"] = 999
    lines[0] = json.dumps(record, sort_keys=True)
    log.write_text("\n".join(lines) + "\n")
    result = verify_chain(tmp_path)
    assert result.valid is False


def test_empty_directory_has_valid_empty_chain(tmp_path):
    result = verify_chain(tmp_path)
    assert result.valid is True
    assert result.event_count == 0
