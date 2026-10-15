from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field


class VirusTotalConfig(BaseModel):
    api_key_env: str = "VIRUSTOTAL_API_KEY"
    enabled: bool = False


class ChecksConfig(BaseModel):
    test: list[list[str]] = Field(default_factory=list)
    build: list[list[str]] = Field(default_factory=list)
    sast: list[list[str]] = Field(default_factory=list)
    secrets: list[list[str]] = Field(default_factory=list)

    def as_dict(self) -> dict[str, list[list[str]]]:
        return {"test": self.test, "build": self.build, "sast": self.sast, "secrets": self.secrets}


class TrustPatchConfig(BaseModel):
    """Typed, validated shape for `config/*.yaml`. Unknown fields are rejected so
    a typo or stale key fails loudly instead of being silently ignored."""

    model_config = {"extra": "forbid"}

    project_name: str = "project"
    artifacts_dir: str = ".trustpatch"
    virustotal: VirusTotalConfig = Field(default_factory=VirusTotalConfig)
    checks: ChecksConfig = Field(default_factory=ChecksConfig)


def load_config(path: Path | None) -> TrustPatchConfig:
    if path is None or not path.exists():
        return TrustPatchConfig()
    data: dict[str, Any] = yaml.safe_load(path.read_text()) or {}
    return TrustPatchConfig.model_validate(data)


def json_schema() -> dict[str, Any]:
    return TrustPatchConfig.model_json_schema()


DEFAULT_APPROVAL_REQUIRED = [
    "major_version",
    "cryptography",
    "authentication",
    "database",
    "native_library",
    "runtime_security_dependency",
    "build_toolchain",
    "ci_security",
    "infrastructure",
    "low_confidence",
]


class ApprovalPolicyConfig(BaseModel):
    required_for: list[str] = Field(default_factory=lambda: list(DEFAULT_APPROVAL_REQUIRED))


class RiskPolicyConfig(BaseModel):
    auto_apply_maximum: Literal["low", "medium", "high"] = "low"
    fail_closed: bool = True


class ExecutionPolicyConfig(BaseModel):
    require_lockfile_refresh: bool = True


class SourcesPolicyConfig(BaseModel):
    mitre_attack: bool = True
    lolbas: bool = True
    virustotal: bool = True


class PolicyFile(BaseModel):
    """Typed, validated shape for `policies/*.yaml`. Unknown fields are rejected
    (SR-007: a typo or stray key in a security policy must fail loudly, not be
    silently ignored and leave the policy weaker than intended)."""

    model_config = {"extra": "forbid"}

    approval: ApprovalPolicyConfig = Field(default_factory=ApprovalPolicyConfig)
    risk: RiskPolicyConfig = Field(default_factory=RiskPolicyConfig)
    execution: ExecutionPolicyConfig = Field(default_factory=ExecutionPolicyConfig)
    sources: SourcesPolicyConfig = Field(default_factory=SourcesPolicyConfig)


def load_policy_file(path: Path | None) -> PolicyFile:
    if path is None or not path.exists():
        return PolicyFile()
    data: dict[str, Any] = yaml.safe_load(path.read_text()) or {}
    return PolicyFile.model_validate(data)


def policy_json_schema() -> dict[str, Any]:
    return PolicyFile.model_json_schema()
