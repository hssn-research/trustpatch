from pathlib import Path

import pytest
from pydantic import ValidationError

from trustpatch.config import TrustPatchConfig, json_schema, load_config


def test_load_config_from_example_yaml():
    config = load_config(Path("config/example.yaml"))
    assert config.project_name == "example"
    assert config.checks.test == []


def test_load_config_missing_file_returns_defaults(tmp_path):
    config = load_config(tmp_path / "nonexistent.yaml")
    assert config.project_name == "project"


def test_unknown_field_is_rejected():
    with pytest.raises(ValidationError):
        TrustPatchConfig.model_validate({"not_a_real_field": True})


def test_json_schema_is_generatable():
    schema = json_schema()
    assert schema["title"] == "TrustPatchConfig"
