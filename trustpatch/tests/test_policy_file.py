from pathlib import Path

import pytest
from pydantic import ValidationError

from trustpatch.config import PolicyFile, load_policy_file, policy_json_schema
from trustpatch.policy import Policy


def test_load_policy_file_from_default_yaml():
    parsed = load_policy_file(Path("policies/default.yaml"))
    assert parsed.risk.auto_apply_maximum == "low"
    assert "major_version" in parsed.approval.required_for


def test_missing_policy_file_uses_safe_defaults(tmp_path):
    parsed = load_policy_file(tmp_path / "missing.yaml")
    assert parsed.risk.fail_closed is True
    assert "major_version" in parsed.approval.required_for


def test_unknown_key_in_policy_file_is_rejected():
    with pytest.raises(ValidationError):
        PolicyFile.model_validate({"not_a_real_section": True})


def test_policy_class_still_exposes_same_public_attributes():
    policy = Policy(Path("policies/default.yaml"))
    assert policy.fail_closed is True
    assert policy.auto_max == "low"
    assert policy.require_lockfile_refresh is True
    assert "major_version" in policy.required_for


def test_policy_schema_is_generatable():
    schema = policy_json_schema()
    assert schema["title"] == "PolicyFile"


def test_invalid_auto_apply_maximum_value_is_rejected():
    with pytest.raises(ValidationError):
        PolicyFile.model_validate({"risk": {"auto_apply_maximum": "lwo"}})  # typo
