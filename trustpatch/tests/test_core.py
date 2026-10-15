import json
from pathlib import Path

from trustpatch.discovery import detect_manifests, inventory
from trustpatch.integrations.sources import VirusTotalSource
from trustpatch.models import Candidate
from trustpatch.policy import Policy


def fixture(tmp_path: Path) -> Path:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"express": "4.18.2"}, "devDependencies": {"vitest": "1.0.0"}})
    )
    (tmp_path / "package-lock.json").write_text("{}")
    return tmp_path


def test_detect_and_inventory_node(tmp_path):
    root = fixture(tmp_path)
    manifests = detect_manifests(root)
    assert manifests[0].ecosystem == "node"
    deps = inventory(root, manifests)
    assert {(d.name, d.scope) for d in deps} == {("express", "runtime"), ("vitest", "development")}


def test_policy_is_fail_closed_for_major_security_change(tmp_path):
    dep = inventory(fixture(tmp_path))[0]
    candidate = Candidate("u1", dep, "5.0.0")
    result = Policy(Path("policies/default.yaml")).evaluate(candidate)
    assert result.risk == "high"
    assert result.approval_required is True


def test_virustotal_does_not_claim_evidence_without_key():
    result = VirusTotalSource(api_key=None).lookup_hash("a" * 64)
    assert result["status"] == "not_configured"
