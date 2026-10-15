import httpx
import pytest

from trustpatch.integrations.osv import OsvSource, minimal_fixed_version, normalize
from trustpatch.integrations.sources import SourceError
from trustpatch.models import Advisory

RAW_GHSA = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "summary": "Example ReDoS vulnerability",
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "express"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.19.0"}]}],
        }
    ],
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
    "references": [{"url": "https://example.invalid/advisory"}],
}


def test_normalize_extracts_fixed_version_and_range():
    advisory = normalize(RAW_GHSA, "express", "node")
    assert advisory.id == "GHSA-xxxx-yyyy-zzzz"
    assert advisory.fixed_versions == ["4.19.0"]
    assert advisory.affected_range == ">=0,<4.19.0"
    assert advisory.severity.startswith("CVSS_V3:")
    assert advisory.evidence_url == "https://example.invalid/advisory"


def test_normalize_ignores_unrelated_package_entries():
    raw = {
        "id": "GHSA-other",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "not-express"}, "ranges": []}],
    }
    advisory = normalize(raw, "express", "node")
    assert advisory.fixed_versions == []
    assert advisory.affected_range is None


def test_minimal_fixed_version_picks_smallest_version_at_or_above_current_satisfying_all():
    advisories = [
        Advisory("A1", "", "high", None, ["4.19.0", "5.0.0"], "osv.dev"),
        Advisory("A2", "", "high", None, ["4.20.0"], "osv.dev"),
    ]
    assert minimal_fixed_version(advisories, "4.0.0") == "4.20.0"


def test_minimal_fixed_version_returns_none_when_unresolvable():
    advisories = [Advisory("A1", "", "high", None, [], "osv.dev")]
    assert minimal_fixed_version(advisories, "1.0.0") is None


# --- Retry/backoff (docs/TODO.md Phase 3: previously missing for OSV) ---------


def test_query_retries_transient_5xx_then_succeeds(monkeypatch):
    """A single transient OSV error must not immediately downgrade the
    dependency to 'unassessed' — the same bounded-retry behavior the ATT&CK/
    LOLBAS/VirusTotal adapters already have."""
    calls = {"n": 0}

    def flaky(url, json=None, timeout=None):
        calls["n"] += 1
        if calls["n"] < 2:
            return httpx.Response(503, request=httpx.Request("POST", url))
        return httpx.Response(200, json={"vulns": [RAW_GHSA]}, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "post", flaky)
    source = OsvSource(attempts=3, sleep_fn=lambda _: None)
    result = source.query("express", "4.0.0", "node")
    assert calls["n"] == 2
    assert result == [RAW_GHSA]


def test_query_gives_up_after_bounded_attempts_and_fails_closed(monkeypatch):
    """Once retries are exhausted, OSV unavailability must raise SourceError —
    never silently return an empty (falsely "clean") vuln list."""
    calls = {"n": 0}

    def always_fails(url, json=None, timeout=None):
        calls["n"] += 1
        return httpx.Response(503, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "post", always_fails)
    source = OsvSource(attempts=3, sleep_fn=lambda _: None)
    with pytest.raises(SourceError):
        source.query("express", "4.0.0", "node")
    assert calls["n"] == 3
