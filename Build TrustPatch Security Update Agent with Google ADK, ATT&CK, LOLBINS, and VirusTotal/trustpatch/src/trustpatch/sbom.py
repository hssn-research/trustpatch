from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from .models import Dependency

_PURL_TYPE = {"python": "pypi", "node": "npm", "go": "golang", "rust": "cargo"}


def _purl(dep: Dependency) -> str:
    ptype = _PURL_TYPE.get(dep.ecosystem, "generic")
    version = dep.version if dep.version not in ("*", "") else None
    suffix = f"@{version}" if version else ""
    return f"pkg:{ptype}/{dep.name}{suffix}"


def generate(project_name: str, deps: list[Dependency]) -> dict[str, Any]:
    """Generate a minimal CycloneDX 1.5-shaped SBOM. Not a full validator-certified
    implementation, but structurally compatible for downstream tooling."""
    components = [
        {
            "type": "library",
            "name": dep.name,
            "version": dep.version if dep.version not in ("*", "") else "unknown",
            "purl": _purl(dep),
            "scope": "required" if dep.scope == "runtime" else "optional",
            "properties": [
                {"name": "trustpatch:ecosystem", "value": dep.ecosystem},
                {"name": "trustpatch:direct", "value": str(dep.direct).lower()},
                {"name": "trustpatch:source", "value": dep.source},
            ],
        }
        for dep in deps
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "component": {"type": "application", "name": project_name},
        },
        "components": components,
    }


def diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Compare two SBOMs by (name, ecosystem) component key, independent of
    generation order, and report added/removed/changed entries."""

    def index(sbom: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
        result = {}
        for component in sbom.get("components", []):
            ecosystem = next(
                (p["value"] for p in component.get("properties", []) if p["name"] == "trustpatch:ecosystem"), ""
            )
            result[(component["name"], ecosystem)] = component
        return result

    before_index, after_index = index(before), index(after)
    added = [after_index[k] for k in after_index.keys() - before_index.keys()]
    removed = [before_index[k] for k in before_index.keys() - after_index.keys()]
    changed = [
        {"name": k[0], "ecosystem": k[1], "before": before_index[k]["version"], "after": after_index[k]["version"]}
        for k in before_index.keys() & after_index.keys()
        if before_index[k]["version"] != after_index[k]["version"]
    ]
    return {"added": added, "removed": removed, "changed": changed}
