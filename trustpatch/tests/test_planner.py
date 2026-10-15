from pathlib import Path

from trustpatch.models import Advisory, Dependency, Manifest
from trustpatch.planner import Assessment, build_candidate, plan_project
from trustpatch.policy import Policy


class FakeOsv:
    def __init__(self, vulns_by_name: dict[str, list[dict]]):
        self.vulns_by_name = vulns_by_name

    def query(self, name, version, ecosystem):
        return self.vulns_by_name.get(name, [])


def test_build_candidate_security_fix_proposes_minimal_fixed_version():
    dep = Dependency("express", "4.0.0", "node", True, "runtime", "package.json")
    advisory = Advisory("GHSA-1", "", "high", None, ["4.19.0"], "osv.dev")
    assessment = Assessment(dep, advisories=[advisory], advisory_lookup_ok=True, latest_known=None)
    candidate = build_candidate(assessment, [Manifest("node", "package.json", "package-lock.json", "npm")])
    assert candidate is not None
    assert candidate.proposed_version == "4.19.0"
    assert candidate.reason == "security_fix"
    assert candidate.confidence == "confirmed"
    assert set(candidate.expected_files) == {"package.json", "package-lock.json"}


def test_build_candidate_unresolved_when_no_fixed_version_known():
    dep = Dependency("express", "4.0.0", "node", True, "runtime", "package.json")
    advisory = Advisory("GHSA-1", "", "high", None, [], "osv.dev")
    assessment = Assessment(dep, advisories=[advisory], advisory_lookup_ok=True, latest_known=None)
    candidate = build_candidate(assessment, [])
    assert candidate is not None
    assert candidate.confidence == "unresolved"
    assert candidate.proposed_version == dep.version


def test_build_candidate_returns_none_when_up_to_date():
    dep = Dependency("express", "4.19.0", "node", True, "runtime", "package.json")
    assessment = Assessment(dep, advisories=[], advisory_lookup_ok=True, latest_known="4.19.0")
    assert build_candidate(assessment, []) is None


def test_plan_project_marks_osv_failures_as_unassessed_not_clean(monkeypatch):
    dep = Dependency("express", "4.0.0", "node", True, "runtime", "package.json")

    class FailingOsv:
        def query(self, *a, **k):
            from trustpatch.integrations.sources import SourceError

            raise SourceError("boom")

    monkeypatch.setattr("trustpatch.planner.latest_version", lambda *a, **k: None)
    result = plan_project([dep], [], Policy(Path("policies/default.yaml")), osv=FailingOsv())
    assert result["candidates"] == []
    assert result["unassessed"] == [{"name": "express", "version": "4.0.0", "reason": "osv_unavailable"}]


def test_plan_project_end_to_end_with_fake_advisory(monkeypatch):
    dep = Dependency("express", "4.0.0", "node", True, "runtime", "package.json")
    fake = FakeOsv(
        {
            "express": [
                {
                    "id": "GHSA-1",
                    "affected": [
                        {
                            "package": {"ecosystem": "npm", "name": "express"},
                            "ranges": [{"type": "SEMVER", "events": [{"fixed": "4.19.0"}]}],
                        }
                    ],
                }
            ]
        }
    )
    monkeypatch.setattr("trustpatch.planner.latest_version", lambda *a, **k: None)
    result = plan_project([dep], [], Policy(Path("policies/default.yaml")), osv=fake)
    assert len(result["candidates"]) == 1
    candidate = result["candidates"][0]
    assert candidate["proposed_version"] == "4.19.0"
    assert candidate["approval_required"] is True
