from pathlib import Path

from trustpatch.discovery import detect_manifests, inventory


def test_pyproject_dependency_version_is_extracted_not_wildcarded(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["requests>=2.31.0", "httpx==0.27.0"]\n'
        '[project.optional-dependencies]\ndev = ["pytest>=8.0"]\n'
    )
    deps = inventory(tmp_path, detect_manifests(tmp_path))
    by_name = {d.name: d for d in deps}
    assert by_name["requests"].version == "2.31.0"
    assert by_name["httpx"].version == "0.27.0"
    assert by_name["pytest"].scope == "development"


def test_go_mod_direct_and_indirect_dependencies(tmp_path: Path):
    (tmp_path / "go.mod").write_text(
        "module example.com/foo\n\ngo 1.21\n\n"
        "require github.com/pkg/errors v0.9.1\n\n"
        "require (\n"
        "\tgithub.com/gin-gonic/gin v1.9.1\n"
        "\tgolang.org/x/text v0.14.0 // indirect\n"
        ")\n"
    )
    deps = inventory(tmp_path, detect_manifests(tmp_path))
    by_name = {d.name: d for d in deps}
    assert by_name["github.com/pkg/errors"].version == "0.9.1"
    assert by_name["github.com/pkg/errors"].direct is True
    assert by_name["golang.org/x/text"].direct is False
    assert by_name["github.com/gin-gonic/gin"].version == "1.9.1"


def test_cargo_toml_dependencies(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text(
        '[dependencies]\nserde = "1.0"\ntokio = { version = "1.38", features = ["full"] }\n'
        '[dev-dependencies]\nmockall = "0.11"\n'
    )
    deps = inventory(tmp_path, detect_manifests(tmp_path))
    by_name = {d.name: d for d in deps}
    assert by_name["serde"].version == "1.0"
    assert by_name["tokio"].version == "1.38"
    assert by_name["mockall"].scope == "development"
