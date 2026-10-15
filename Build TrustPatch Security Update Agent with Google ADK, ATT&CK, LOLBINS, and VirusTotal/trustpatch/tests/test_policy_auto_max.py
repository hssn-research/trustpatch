"""Regression tests for a real bug found during review: `risk.auto_apply_maximum`
was parsed from policy YAML and stored on `Policy.auto_max`, but `evaluate()`
never actually consulted it — it hardcoded `candidate.risk != "low"`, which only
happened to match the *default* auto_max value ("low"). A policy configured with
a different threshold was silently ignored."""

from pathlib import Path

from trustpatch.models import Advisory, Candidate, Dependency
from trustpatch.policy import Policy

DEP = Dependency("some-lib", "1.0.0", "node", True, "runtime", "package.json")


def make_policy(tmp_path: Path, auto_apply_maximum: str) -> Policy:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(f"risk:\n  auto_apply_maximum: {auto_apply_maximum}\n")
    return Policy(policy_file)


def medium_risk_candidate() -> Candidate:
    # One advisory (no major bump, no name-heuristic match) -> exactly one risk
    # reason -> risk == "medium" per policy.py's `len(reasons) >= 2 or major`.
    advisory = Advisory("GHSA-1", "", "moderate", None, ["1.1.0"], "osv.dev")
    return Candidate(update_id="u1", dependency=DEP, proposed_version="1.1.0", advisories=[advisory])


def high_risk_candidate() -> Candidate:
    # Major version bump + advisory -> two reasons -> risk == "high".
    advisory = Advisory("GHSA-1", "", "critical", None, ["2.0.0"], "osv.dev")
    return Candidate(update_id="u1", dependency=DEP, proposed_version="2.0.0", advisories=[advisory])


def test_default_low_auto_max_requires_approval_for_medium_risk(tmp_path):
    policy = make_policy(tmp_path, "low")
    result = policy.evaluate(medium_risk_candidate())
    assert result.risk == "medium"
    assert result.approval_required is True


def test_auto_max_medium_allows_medium_risk_without_approval(tmp_path):
    """The actual bug fix: configuring auto_apply_maximum: medium must genuinely
    let a medium-risk candidate (with no matching required_for category) skip
    the approval requirement — before the fix, this was silently ignored."""
    policy = make_policy(tmp_path, "medium")
    result = policy.evaluate(medium_risk_candidate())
    assert result.risk == "medium"
    assert result.approval_required is False


def test_auto_max_medium_still_requires_approval_for_high_risk(tmp_path):
    policy = make_policy(tmp_path, "medium")
    result = policy.evaluate(high_risk_candidate())
    assert result.risk == "high"
    assert result.approval_required is True


def test_auto_max_high_allows_high_risk_without_approval(tmp_path):
    """An operator can deliberately opt into a permissive threshold — the
    setting must be honored symmetrically, not just fail closed.

    `required_for` is explicitly emptied here to isolate the auto_max
    mechanism: by default, a high-risk major-version bump also matches the
    `major_version` category, which independently forces approval regardless
    of auto_max (see the next test) — that's correct and intentional, but
    would make this specific assertion about auto_max untestable in isolation
    without also controlling for it.
    """
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("risk:\n  auto_apply_maximum: high\napproval:\n  required_for: []\n")
    policy = Policy(policy_file)
    result = policy.evaluate(high_risk_candidate())
    assert result.risk == "high"
    assert result.approval_required is False


def test_required_for_category_still_forces_approval_even_under_permissive_auto_max(tmp_path):
    """auto_apply_maximum must never override an explicit required_for category
    match — e.g. a major version bump on a database driver still needs approval
    even if the site has configured a very permissive risk threshold."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("risk:\n  auto_apply_maximum: high\napproval:\n  required_for: [database]\n")
    policy = Policy(policy_file)
    dep = Dependency("postgres-driver", "1.0.0", "node", True, "runtime", "package.json")
    candidate = Candidate(update_id="u1", dependency=dep, proposed_version="1.0.1")
    result = policy.evaluate(candidate)
    assert result.approval_required is True
