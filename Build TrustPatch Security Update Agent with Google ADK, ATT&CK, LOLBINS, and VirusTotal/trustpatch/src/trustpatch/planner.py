from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .integrations.osv import OsvSource, minimal_fixed_version, normalize
from .integrations.registry import latest_version
from .integrations.sources import SourceError
from .models import Advisory, Candidate, Dependency, Manifest
from .policy import Policy
from .versions import classify_bump, version_key


@dataclass
class Assessment:
    dependency: Dependency
    advisories: list[Advisory] = field(default_factory=list)
    advisory_lookup_ok: bool = True
    latest_known: str | None = None


def assess_dependency(dep: Dependency, osv: OsvSource | None = None, check_latest: bool = True) -> Assessment:
    """Query trusted vulnerability intelligence for one dependency. Never infers
    vulnerability status from the package name; a failed lookup is recorded as
    unavailable rather than treated as "clean" (fail-closed).

    `check_latest` additionally queries the package registry for the newest
    published version (used by the planner's outdated-dependency detection). The
    verifier's post-update rescan only needs vulnerability status, so it passes
    check_latest=False to avoid an unnecessary registry call."""
    osv = osv or OsvSource()
    advisories: list[Advisory] = []
    lookup_ok = True
    if dep.version not in ("*", ""):
        try:
            raw = osv.query(dep.name, dep.version, dep.ecosystem)
            advisories = [normalize(v, dep.name, dep.ecosystem) for v in raw]
        except SourceError:
            lookup_ok = False
    latest = None
    if check_latest and dep.version not in ("*", ""):
        latest = latest_version(dep.name, dep.ecosystem)
    return Assessment(dep, advisories, lookup_ok, latest)


def _expected_files(dep: Dependency, manifests: list[Manifest]) -> list[str]:
    files = {dep.source}
    for manifest in manifests:
        if manifest.ecosystem == dep.ecosystem:
            files.add(manifest.path)
            if manifest.lockfile:
                files.add(manifest.lockfile)
    return sorted(files)


def build_candidate(assessment: Assessment, manifests: list[Manifest]) -> Candidate | None:
    """Map an assessment to at most one update candidate. Returns None when there
    is nothing to propose (up to date and no vulnerability evidence)."""
    dep = assessment.dependency
    update_id = "upd_" + dep.name.replace("/", "_")
    expected_files = _expected_files(dep, manifests)

    if assessment.advisories:
        fixed = minimal_fixed_version(assessment.advisories, dep.version)
        if fixed is not None:
            proposed, confidence = fixed, "confirmed"
        else:
            proposed, confidence = dep.version, "unresolved"
        return Candidate(
            update_id=update_id,
            dependency=dep,
            proposed_version=proposed,
            advisories=assessment.advisories,
            expected_files=expected_files,
            reason="security_fix",
            update_kind=classify_bump(dep.version, proposed),
            confidence=confidence,
            test_plan=["unit", "build", "dependency_vulnerability_rescan"],
        )

    if assessment.latest_known and version_key(assessment.latest_known) > version_key(dep.version):
        return Candidate(
            update_id=update_id,
            dependency=dep,
            proposed_version=assessment.latest_known,
            advisories=[],
            expected_files=expected_files,
            reason="maintenance_update",
            update_kind=classify_bump(dep.version, assessment.latest_known),
            confidence="confirmed",
            test_plan=["unit", "build"],
        )

    return None


def plan_project(
    deps: list[Dependency], manifests: list[Manifest], policy: Policy, osv: OsvSource | None = None
) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    up_to_date: list[dict[str, str]] = []
    unassessed: list[dict[str, str]] = []
    for dep in deps:
        if dep.version in ("*", ""):
            unassessed.append({"name": dep.name, "version": dep.version, "reason": "version_not_pinned"})
            continue
        assessment = assess_dependency(dep, osv)
        if not assessment.advisory_lookup_ok:
            unassessed.append({"name": dep.name, "version": dep.version, "reason": "osv_unavailable"})
            continue
        candidate = build_candidate(assessment, manifests)
        if candidate is None:
            up_to_date.append({"name": dep.name, "version": dep.version})
        else:
            candidates.append(policy.evaluate(candidate).to_dict())
    return {"candidates": candidates, "up_to_date": up_to_date, "unassessed": unassessed}
