from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

@dataclass(frozen=True)
class Manifest:
    ecosystem: str
    path: str
    lockfile: str | None
    manager: str

@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    ecosystem: str
    direct: bool
    scope: str
    source: str
    parent: str | None = None
    integrity: str | None = None

@dataclass(frozen=True)
class Advisory:
    id: str
    summary: str
    severity: str
    affected_range: str | None
    fixed_versions: list[str]
    source: str
    evidence_url: str | None = None

@dataclass
class Candidate:
    update_id: str
    dependency: Dependency
    proposed_version: str
    advisories: list[Advisory] = field(default_factory=list)
    risk: str = "medium"
    risk_reasons: list[str] = field(default_factory=list)
    approval_required: bool = True
    expected_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["dependency"] = asdict(self.dependency)
        data["advisories"] = [asdict(item) for item in self.advisories]
        return data
