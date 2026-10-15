import json

import pytest

from trustpatch.executor import ExecutorError, apply_manifest_update
from trustpatch.models import Candidate, Dependency


def make_candidate(dep: Dependency, proposed: str) -> Candidate:
    return Candidate(update_id="u1", dependency=dep, proposed_version=proposed, expected_files=[dep.source])


def test_apply_manifest_update_node_package_json(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "4.0.0"}}))
    dep = Dependency("express", "4.0.0", "node", True, "runtime", "package.json")
    changed = apply_manifest_update(tmp_path, make_candidate(dep, "4.19.0"))
    assert changed == ["package.json"]
    data = json.loads((tmp_path / "package.json").read_text())
    assert data["dependencies"]["express"] == "4.19.0"


def test_apply_manifest_update_edits_manifest_not_lockfile_when_source_is_lockfile(tmp_path):
    """Regression test: discovery.py sets Dependency.source to the lockfile name
    when a lockfile is present (for provenance), not the manifest. A real project
    with a lockfile must still get its package.json edited, not its lockfile."""
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "4.18.2"}}))
    (tmp_path / "package-lock.json").write_text("{}")
    dep = Dependency("express", "4.18.2", "node", True, "runtime", "package-lock.json")
    candidate = Candidate(
        update_id="u1",
        dependency=dep,
        proposed_version="4.20.0",
        expected_files=["package-lock.json", "package.json"],
    )
    changed = apply_manifest_update(tmp_path, candidate)
    assert changed == ["package.json"]
    data = json.loads((tmp_path / "package.json").read_text())
    assert data["dependencies"]["express"] == "4.20.0"
    assert (tmp_path / "package-lock.json").read_text() == "{}"


def test_apply_manifest_update_requirements_txt(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nother==1.0\n")
    dep = Dependency("requests", "2.31.0", "python", True, "runtime", "requirements.txt")
    apply_manifest_update(tmp_path, make_candidate(dep, "2.32.4"))
    lines = (tmp_path / "requirements.txt").read_text().splitlines()
    assert "requests==2.32.4" in lines
    assert "other==1.0" in lines


def test_apply_manifest_update_pyproject_toml(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["requests>=2.31.0"]\n')
    dep = Dependency("requests", "2.31.0", "python", True, "runtime", "pyproject.toml")
    apply_manifest_update(tmp_path, make_candidate(dep, "2.32.4"))
    text = (tmp_path / "pyproject.toml").read_text()
    assert "requests>=2.32.4" in text


def test_apply_manifest_update_missing_dependency_raises(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {}}))
    dep = Dependency("express", "4.0.0", "node", True, "runtime", "package.json")
    with pytest.raises(ExecutorError):
        apply_manifest_update(tmp_path, make_candidate(dep, "4.19.0"))


def test_requirements_txt_refuses_to_touch_hash_pinned_line(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0 --hash=sha256:deadbeef\n")
    dep = Dependency("requests", "2.31.0", "python", True, "runtime", "requirements.txt")
    with pytest.raises(ExecutorError, match="hash-pinned"):
        apply_manifest_update(tmp_path, make_candidate(dep, "2.32.4"))
    assert "sha256:deadbeef" in (tmp_path / "requirements.txt").read_text()


def test_requirements_txt_refuses_compound_constraint(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests>=2.0,<3.0\n")
    dep = Dependency("requests", "2.31.0", "python", True, "runtime", "requirements.txt")
    with pytest.raises(ExecutorError, match="compound"):
        apply_manifest_update(tmp_path, make_candidate(dep, "2.32.4"))


def test_requirements_txt_preserves_marker_and_comment(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0; python_version >= '3.8'  # pinned for security\n")
    dep = Dependency("requests", "2.31.0", "python", True, "runtime", "requirements.txt")
    apply_manifest_update(tmp_path, make_candidate(dep, "2.32.4"))
    text = (tmp_path / "requirements.txt").read_text()
    assert "requests==2.32.4" in text
    assert "python_version >= '3.8'" in text
    assert "pinned for security" in text


def test_requirements_txt_refuses_marker_only_line_with_no_version(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests; python_version >= '3.8'\n")
    dep = Dependency("requests", "0.0.0", "python", True, "runtime", "requirements.txt")
    with pytest.raises(ExecutorError):
        apply_manifest_update(tmp_path, make_candidate(dep, "2.32.4"))


def test_pyproject_toml_refuses_compound_constraint(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["requests>=2.0,<3.0"]\n')
    dep = Dependency("requests", "2.31.0", "python", True, "runtime", "pyproject.toml")
    with pytest.raises(ExecutorError, match="compound"):
        apply_manifest_update(tmp_path, make_candidate(dep, "2.32.4"))


def test_pyproject_toml_preserves_marker(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project]\ndependencies = [\"requests>=2.31.0; python_version >= '3.8'\"]\n"
    )
    dep = Dependency("requests", "2.31.0", "python", True, "runtime", "pyproject.toml")
    apply_manifest_update(tmp_path, make_candidate(dep, "2.32.4"))
    text = (tmp_path / "pyproject.toml").read_text()
    assert "requests>=2.32.4" in text
    assert "python_version >= '3.8'" in text
