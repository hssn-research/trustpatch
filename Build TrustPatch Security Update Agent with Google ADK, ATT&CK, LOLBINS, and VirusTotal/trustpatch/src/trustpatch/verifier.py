from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import sbom as sbom_module
from .checks import CheckResult, run_all
from .constants import CONTROL_DIR_NAME
from .discovery import detect_manifests, inventory
from .integrations.osv import OsvSource
from .models import Candidate, Dependency
from .planner import assess_dependency
from .sandbox import Sandbox, changed_files

REQUIRE_LOCKFILE_REFRESH_DEFAULT = True


@dataclass
class VerificationReport:
    passed: bool
    update_id: str
    reasons: list[str] = field(default_factory=list)
    resolved_version: str | None = None
    actual_changed_files: list[str] = field(default_factory=list)
    unexpected_files: list[str] = field(default_factory=list)
    lockfile_refreshed: bool | None = None
    vulnerability_status: str = "unknown"
    check_results: list[CheckResult] = field(default_factory=list)
    sbom_delta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "update_id": self.update_id,
            "reasons": self.reasons,
            "resolved_version": self.resolved_version,
            "actual_changed_files": self.actual_changed_files,
            "unexpected_files": self.unexpected_files,
            "lockfile_refreshed": self.lockfile_refreshed,
            "vulnerability_status": self.vulnerability_status,
            "check_results": [vars(r) for r in self.check_results],
            "sbom_delta": self.sbom_delta,
        }


def verify(
    sandbox: Sandbox,
    candidate: Candidate,
    checks: dict[str, list[list[str]]] | None = None,
    require_lockfile_refresh: bool = REQUIRE_LOCKFILE_REFRESH_DEFAULT,
    osv: OsvSource | None = None,
    check_timeout: float = 300,
    before_deps: list[Dependency] | None = None,
) -> VerificationReport:
    """Independently reconstruct the resolved state from the worktree rather than
    trusting the executor's own report. This module must not import trustpatch.executor
    or otherwise rely on executor-internal state — only on-disk facts and re-run tools.
    Fail-closed: any ambiguous, missing, or failed evidence makes `passed` False.

    `before_deps` lets a caller supply the pre-mutation dependency inventory
    explicitly. This matters when `sandbox.root` and `sandbox.worktree` are the
    same tree (the final re-verification after `apply` mutates the primary tree
    in place) — in that case re-reading `sandbox.root` from disk would read the
    *already-mutated* state and silently defeat the SBOM before/after comparison.
    Defaults to reading `sandbox.root` from disk, which is correct for the normal
    prepare-only sandbox case where root is untouched.
    """
    reasons: list[str] = []
    dep = candidate.dependency

    control_prefix = f"{CONTROL_DIR_NAME}/"
    actual_files = [f for f in changed_files(sandbox) if not f.startswith(control_prefix)]
    unexpected = sorted(set(actual_files) - set(candidate.expected_files))
    if unexpected:
        reasons.append(f"unexpected file changes: {unexpected}")

    manifests = detect_manifests(sandbox.worktree)
    worktree_deps = inventory(sandbox.worktree, manifests)
    match = next((d for d in worktree_deps if d.name == dep.name and d.ecosystem == dep.ecosystem), None)
    resolved_version = match.version if match else None
    if resolved_version != candidate.proposed_version:
        reasons.append(f"resolved version {resolved_version!r} does not match expected {candidate.proposed_version!r}")

    manifest = next((m for m in manifests if m.ecosystem == dep.ecosystem), None)
    lockfile_refreshed: bool | None = None
    if manifest and manifest.lockfile:
        lockfile_refreshed = manifest.lockfile in actual_files
        if not lockfile_refreshed and require_lockfile_refresh:
            reasons.append(
                f"lockfile {manifest.lockfile} was not refreshed; dependency manager may still resolve the old version"
            )

    vulnerability_status = "not_applicable"
    if candidate.reason == "security_fix":
        if match is None:
            vulnerability_status = "unknown_dependency_missing"
        else:
            rescan = assess_dependency(match, osv, check_latest=False)
            if not rescan.advisory_lookup_ok:
                vulnerability_status = "rescan_unavailable"
                reasons.append("post-update vulnerability rescan was unavailable")
            elif rescan.advisories:
                vulnerability_status = "still_vulnerable"
                reasons.append(f"{len(rescan.advisories)} advisory(ies) still apply after update")
            else:
                vulnerability_status = "resolved"

    check_results = run_all(checks or {}, sandbox.worktree, check_timeout) if checks else []
    failed_checks = [c for c in check_results if not c.passed]
    if failed_checks:
        reasons.append(f"{len(failed_checks)} configured check(s) failed")

    before_sbom = sbom_module.generate("before", before_deps if before_deps is not None else inventory(sandbox.root))
    after_sbom = sbom_module.generate("after", worktree_deps)
    delta = sbom_module.diff(before_sbom, after_sbom)
    unexpected_component_changes = [c for c in delta["changed"] if c["name"] != dep.name]
    if unexpected_component_changes:
        reasons.append(f"unexpected SBOM component changes: {unexpected_component_changes}")
    if delta["added"]:
        reasons.append(f"unexpected new SBOM component(s): {[c['name'] for c in delta['added']]}")
    if delta["removed"]:
        reasons.append(f"unexpected removed SBOM component(s): {[c['name'] for c in delta['removed']]}")

    passed = not reasons
    return VerificationReport(
        passed=passed,
        update_id=candidate.update_id,
        reasons=reasons,
        resolved_version=resolved_version,
        actual_changed_files=actual_files,
        unexpected_files=unexpected,
        lockfile_refreshed=lockfile_refreshed,
        vulnerability_status=vulnerability_status,
        check_results=check_results,
        sbom_delta=delta,
    )
