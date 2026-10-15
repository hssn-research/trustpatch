import json
import shutil
import subprocess

import pytest

from trustpatch import sandbox as sandbox_module
from trustpatch.discovery import detect_manifests, inventory
from trustpatch.executor import apply_manifest_update
from trustpatch.models import Advisory, Candidate, Dependency
from trustpatch.sandbox import Sandbox
from trustpatch.verifier import verify as run_verification

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required for sandbox/worktree tests")


def init_repo(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True)
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "4.0.0"}}, indent=2) + "\n")
    (tmp_path / "package-lock.json").write_text("{}\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=tmp_path, check=True)
    return tmp_path


class NoAdvisoriesOsv:
    def query(self, *args, **kwargs):
        return []


def test_sandbox_create_and_cleanup(tmp_path):
    root = init_repo(tmp_path)
    box = sandbox_module.create(root, "u1")
    assert box.worktree.exists()
    box.cleanup()
    assert not box.worktree.exists()


def test_full_prepare_and_verify_cycle_passes(tmp_path):
    root = init_repo(tmp_path)
    dep = Dependency("express", "4.0.0", "node", True, "runtime", "package.json")
    candidate = Candidate(
        update_id="u1",
        dependency=dep,
        proposed_version="4.19.0",
        advisories=[Advisory("GHSA-1", "", "high", None, ["4.19.0"], "osv.dev")],
        expected_files=["package.json", "package-lock.json"],
        reason="security_fix",
    )
    box = sandbox_module.create(root, "u1")
    try:
        apply_manifest_update(box.worktree, candidate)
        report = run_verification(box, candidate, checks={}, osv=NoAdvisoriesOsv(), require_lockfile_refresh=False)
    finally:
        box.cleanup()
    assert report.resolved_version == "4.19.0"
    assert report.vulnerability_status == "resolved"
    assert report.unexpected_files == []
    assert report.passed is True


def test_unexpected_file_change_fails_verification(tmp_path):
    root = init_repo(tmp_path)
    dep = Dependency("express", "4.0.0", "node", True, "runtime", "package.json")
    candidate = Candidate(
        update_id="u1",
        dependency=dep,
        proposed_version="4.19.0",
        expected_files=["package.json"],
        reason="maintenance_update",
    )
    box = sandbox_module.create(root, "u1")
    try:
        apply_manifest_update(box.worktree, candidate)
        (box.worktree / "unexpected.txt").write_text("surprise")
        report = run_verification(box, candidate, checks={}, osv=NoAdvisoriesOsv(), require_lockfile_refresh=False)
    finally:
        box.cleanup()
    assert report.passed is False
    assert "unexpected.txt" in report.unexpected_files


def test_unexpected_new_dependency_in_sbom_fails_verification(tmp_path):
    """Regression test: the SBOM check only flagged unexpected *version
    changes* to existing components, not entirely new or vanished ones. If a
    manifest edit somehow introduced or dropped a whole dependency entry
    (beyond the single planned version bump — e.g. an executor bug, or a
    tampered worktree), that must fail verification too."""
    root = init_repo(tmp_path)
    dep = Dependency("express", "4.0.0", "node", True, "runtime", "package.json")
    candidate = Candidate(
        update_id="u1",
        dependency=dep,
        proposed_version="4.19.0",
        expected_files=["package.json"],
        reason="maintenance_update",
    )
    box = sandbox_module.create(root, "u1")
    try:
        apply_manifest_update(box.worktree, candidate)
        # Simulate an executor bug that also slipped in an unrelated new dependency.
        manifest = box.worktree / "package.json"
        data = json.loads(manifest.read_text())
        data["dependencies"]["sneaky-extra-package"] = "1.0.0"
        manifest.write_text(json.dumps(data))
        report = run_verification(box, candidate, checks={}, osv=NoAdvisoriesOsv(), require_lockfile_refresh=False)
    finally:
        box.cleanup()
    assert report.passed is False
    assert any("sneaky-extra-package" in reason for reason in report.reasons)


def test_apply_style_verification_needs_explicit_before_deps(tmp_path):
    """When root and worktree are the same tree (the final re-verification after
    `apply` mutates the primary tree in place), the SBOM before/after comparison
    must use the pre-mutation inventory explicitly, not re-read `root` from disk
    — by then it already reflects the *after* state."""
    root = init_repo(tmp_path)
    dep = Dependency("express", "4.0.0", "node", True, "runtime", "package.json")
    candidate = Candidate(
        update_id="u1",
        dependency=dep,
        proposed_version="4.19.0",
        expected_files=["package.json"],
        reason="maintenance_update",
    )
    before_deps = inventory(root, detect_manifests(root))
    apply_manifest_update(root, candidate)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "apply"], cwd=root, check=True)

    pseudo_sandbox = Sandbox(root=root, worktree=root, base_commit="HEAD~1")
    without_before = run_verification(pseudo_sandbox, candidate, checks={}, osv=NoAdvisoriesOsv())
    with_before = run_verification(pseudo_sandbox, candidate, checks={}, osv=NoAdvisoriesOsv(), before_deps=before_deps)
    assert without_before.sbom_delta["changed"] == []
    assert with_before.sbom_delta["changed"] == [
        {"name": "express", "ecosystem": "node", "before": "4.0.0", "after": "4.19.0"}
    ]


def test_apply_style_verification_ignores_own_control_directory(tmp_path):
    """Regression test: the real end-to-end CLI walkthrough found that `apply`'s
    final re-verification (worktree == root, the primary tree) was picking up
    TrustPatch's own uncommitted `.trustpatch/` control-plane files (audit log,
    plan, proposals, verifications, approvals — all written during the normal
    scan/plan/propose/run/approve workflow) as "unexpected file changes" and
    self-triggering a rollback on every apply. `verify()` must exclude its own
    control directory from that comparison."""
    root = init_repo(tmp_path)
    dep = Dependency("express", "4.0.0", "node", True, "runtime", "package.json")
    candidate = Candidate(
        update_id="u1",
        dependency=dep,
        proposed_version="4.19.0",
        expected_files=["package.json"],
        reason="maintenance_update",
    )
    apply_manifest_update(root, candidate)
    subprocess.run(["git", "add", "package.json"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "apply"], cwd=root, check=True)

    # Simulate the accumulated, uncommitted control-plane state a real
    # scan/plan/propose/run/approve workflow leaves behind in the primary tree.
    control = root / ".trustpatch"
    (control / "proposals").mkdir(parents=True)
    (control / "verifications").mkdir(parents=True)
    (control / "approvals").mkdir(parents=True)
    (control / "audit.jsonl").write_text('{"event_id": "evt_1"}\n')
    (control / "plan.json").write_text("{}")
    (control / "proposals" / "u1.json").write_text("{}")
    (control / "verifications" / "u1.json").write_text("{}")
    (control / "approvals" / "u1.json").write_text("{}")

    pseudo_sandbox = Sandbox(root=root, worktree=root, base_commit="HEAD~1")
    report = run_verification(
        pseudo_sandbox, candidate, checks={}, osv=NoAdvisoriesOsv(), require_lockfile_refresh=False
    )
    assert report.unexpected_files == []
    assert report.passed is True
    assert all(not f.startswith(".trustpatch/") for f in report.actual_changed_files)
