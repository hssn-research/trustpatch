from trustpatch import sbom
from trustpatch.models import Dependency


def test_generate_produces_cyclonedx_shaped_components():
    deps = [Dependency("express", "4.18.2", "node", True, "runtime", "package.json")]
    bom = sbom.generate("demo", deps)
    assert bom["bomFormat"] == "CycloneDX"
    component = bom["components"][0]
    assert component["name"] == "express"
    assert component["version"] == "4.18.2"
    assert component["purl"] == "pkg:npm/express@4.18.2"


def test_diff_detects_version_change_add_and_remove():
    before = sbom.generate(
        "demo",
        [
            Dependency("express", "4.18.2", "node", True, "runtime", "package.json"),
            Dependency("lodash", "4.17.0", "node", True, "runtime", "package.json"),
        ],
    )
    after = sbom.generate(
        "demo",
        [
            Dependency("express", "4.19.0", "node", True, "runtime", "package.json"),
            Dependency("chalk", "5.0.0", "node", True, "runtime", "package.json"),
        ],
    )
    delta = sbom.diff(before, after)
    assert delta["changed"] == [{"name": "express", "ecosystem": "node", "before": "4.18.2", "after": "4.19.0"}]
    assert [c["name"] for c in delta["added"]] == ["chalk"]
    assert [c["name"] for c in delta["removed"]] == ["lodash"]
