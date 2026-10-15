"""Tests for docs/DEFENSIVE_SECURITY.md's production requirements: pinned ATT&CK
release, bounded retries, caching with retrieval timestamps, LOLBAS feed-shape
validation, and VirusTotal audit fields / stale-result handling.

Live tests hit the real, public, no-auth ATT&CK and LOLBAS feeds (network
required, skipped otherwise) — they are the most meaningful evidence that
caching and the pinned release actually work against the real service.
VirusTotal requires an API key this environment doesn't have, so its retry/429/
caching logic is tested deterministically by monkeypatching `httpx.get` with
canned responses — real execution of TrustPatch's own retry loop, without
depending on live third-party rate limits.
"""

from __future__ import annotations

import json
import socket

import httpx
import pytest

from trustpatch import cache as cache_module
from trustpatch.integrations.sources import (
    LolbasSource,
    MitreAttackSource,
    SourceError,
    VirusTotalSource,
    _request_with_retry,
)


def _network_available() -> bool:
    try:
        socket.create_connection(("raw.githubusercontent.com", 443), timeout=5).close()
        return True
    except OSError:
        return False


requires_network = pytest.mark.skipif(not _network_available(), reason="network access required")


# --- cache.py --------------------------------------------------------------


def test_cache_round_trip(tmp_path):
    path = tmp_path / "entry.json"
    cache_module.write_cache_atomic(path, {"x": 1}, {"release": "v1"})
    entry = cache_module.read_cache(path, ttl_seconds=3600)
    assert entry is not None
    assert entry.data == {"x": 1}
    assert entry.stale is False
    assert entry.metadata["release"] == "v1"


def test_cache_expires_past_ttl(tmp_path):
    path = tmp_path / "entry.json"
    cache_module.write_cache_atomic(path, {"x": 1})
    entry = cache_module.read_cache(path, ttl_seconds=-1)  # already expired
    assert entry is not None
    assert entry.stale is True
    assert entry.data == {"x": 1}, "a stale cache still returns its data for offline fallback"


def test_cache_missing_file_returns_none(tmp_path):
    assert cache_module.read_cache(tmp_path / "missing.json", ttl_seconds=3600) is None


def test_cache_corrupt_file_returns_none_not_a_crash(tmp_path):
    path = tmp_path / "entry.json"
    path.write_text("{not valid json")
    assert cache_module.read_cache(path, ttl_seconds=3600) is None


def test_cache_write_leaves_no_temp_files_behind(tmp_path):
    path = tmp_path / "entry.json"
    cache_module.write_cache_atomic(path, {"x": 1})
    cache_module.write_cache_atomic(path, {"x": 2})
    leftovers = [p for p in tmp_path.iterdir() if p.name != "entry.json"]
    assert leftovers == []
    assert cache_module.read_cache(path, 3600).data == {"x": 2}


# --- retry logic (deterministic, no real network/sleep) --------------------


def test_retry_succeeds_after_transient_failures(monkeypatch):
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(503, request=httpx.Request("GET", "https://x.invalid"))
        return httpx.Response(200, request=httpx.Request("GET", "https://x.invalid"))

    sleeps: list[float] = []
    response = _request_with_retry(flaky, attempts=5, base_delay=0.01, sleep_fn=sleeps.append)
    assert response.status_code == 200
    assert calls["n"] == 3
    assert len(sleeps) == 2, "should sleep between failed attempts, not after the final success"


def test_retry_gives_up_after_bounded_attempts(monkeypatch):
    calls = {"n": 0}

    def always_503():
        calls["n"] += 1
        return httpx.Response(503, request=httpx.Request("GET", "https://x.invalid"))

    response = _request_with_retry(always_503, attempts=3, base_delay=0.01, sleep_fn=lambda _: None)
    assert response.status_code == 503
    assert calls["n"] == 3, "must stop at the bound, never retry forever"


def test_retry_honors_retry_after_header(monkeypatch):
    calls = {"n": 0}

    def rate_limited():
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "7"}, request=httpx.Request("GET", "https://x.invalid"))
        return httpx.Response(200, request=httpx.Request("GET", "https://x.invalid"))

    sleeps: list[float] = []
    _request_with_retry(rate_limited, attempts=3, base_delay=0.01, sleep_fn=sleeps.append)
    assert sleeps[0] >= 7, "must honor the server's Retry-After, not the default backoff"


def test_retry_does_not_retry_non_retryable_status(monkeypatch):
    calls = {"n": 0}

    def not_found():
        calls["n"] += 1
        return httpx.Response(404, request=httpx.Request("GET", "https://x.invalid"))

    response = _request_with_retry(not_found, attempts=5, base_delay=0.01, sleep_fn=lambda _: None)
    assert response.status_code == 404
    assert calls["n"] == 1, "a definitive 404 must not be retried"


def test_retry_reraises_connection_error_after_bound(monkeypatch):
    def always_fails():
        raise httpx.ConnectError("boom")

    with pytest.raises(httpx.ConnectError):
        _request_with_retry(always_fails, attempts=2, base_delay=0.01, sleep_fn=lambda _: None)


# --- MITRE ATT&CK: pinned release + caching (live) --------------------------


@requires_network
def test_mitre_attack_live_fetch_and_cache(tmp_path):
    cache_path = tmp_path / "mitre_attack.json"
    source = MitreAttackSource(cache_path=cache_path, cache_ttl_seconds=3600)
    first = source.techniques()
    assert first.from_cache is False
    assert first.stale is False
    assert len(first.data) > 100, "the real enterprise ATT&CK bundle has hundreds of techniques"
    assert all(t.get("type") == "attack-pattern" for t in first.data)
    assert first.extra["release"] == source.release

    # Second call must be served from cache, without hitting the network again.
    second = MitreAttackSource(cache_path=cache_path, cache_ttl_seconds=3600).techniques()
    assert second.from_cache is True
    assert second.stale is False
    assert second.data == first.data


def test_mitre_attack_falls_back_to_stale_cache_when_offline(tmp_path):
    cache_path = tmp_path / "mitre_attack.json"
    cache_module.write_cache_atomic(
        cache_path, [{"type": "attack-pattern", "id": "T1000"}], {"release": "v1.0", "retrieved_at": "then"}
    )
    source = MitreAttackSource(
        release="v1.0", cache_path=cache_path, cache_ttl_seconds=-1, attempts=1, sleep_fn=lambda _: None
    )
    source.url = "https://this-host-does-not-exist.invalid/nope.json"
    result = source.techniques()
    assert result.from_cache is True
    assert result.stale is True
    assert result.extra["offline_fallback"] is True
    assert result.data == [{"type": "attack-pattern", "id": "T1000"}]


def test_mitre_attack_raises_when_offline_and_no_cache(tmp_path):
    source = MitreAttackSource(
        cache_path=tmp_path / "missing.json", cache_ttl_seconds=3600, attempts=1, sleep_fn=lambda _: None
    )
    source.url = "https://this-host-does-not-exist.invalid/nope.json"
    with pytest.raises(SourceError):
        source.techniques()


# --- LOLBAS: validation + caching (live) ------------------------------------


@requires_network
def test_lolbas_live_fetch_and_cache(tmp_path):
    cache_path = tmp_path / "lolbas.json"
    source = LolbasSource(cache_path=cache_path, cache_ttl_seconds=3600)
    first = source.binaries()
    assert first.from_cache is False
    assert len(first.data) > 10, "the real LOLBAS feed has many entries"
    assert all(isinstance(entry, dict) for entry in first.data)

    second = LolbasSource(cache_path=cache_path, cache_ttl_seconds=3600).binaries()
    assert second.from_cache is True
    assert second.data == first.data


def test_lolbas_rejects_malformed_feed_shape_instead_of_silently_returning_empty(monkeypatch, tmp_path):
    source = LolbasSource(cache_path=tmp_path / "lolbas.json")
    monkeypatch.setattr(source, "get", lambda: {"unexpected": "shape"})
    with pytest.raises(SourceError, match="unexpected top-level shape"):
        source.binaries()


def test_lolbas_rejects_non_object_entries(monkeypatch, tmp_path):
    source = LolbasSource(cache_path=tmp_path / "lolbas.json")
    monkeypatch.setattr(source, "get", lambda: ["not-an-object", 123])
    with pytest.raises(SourceError, match="must all be objects"):
        source.binaries()


def test_lolbas_accepts_entries_wrapper_shape(monkeypatch, tmp_path):
    source = LolbasSource(cache_path=tmp_path / "lolbas.json")
    monkeypatch.setattr(source, "get", lambda: {"entries": [{"Name": "certutil.exe"}]})
    result = source.binaries()
    assert result.data == [{"Name": "certutil.exe"}]


def test_lolbas_falls_back_to_stale_cache_when_offline(tmp_path):
    cache_path = tmp_path / "lolbas.json"
    cache_module.write_cache_atomic(cache_path, [{"Name": "certutil.exe"}], {"retrieved_at": "then"})
    source = LolbasSource(cache_path=cache_path, cache_ttl_seconds=-1, attempts=1, sleep_fn=lambda _: None)
    source.url = "https://this-host-does-not-exist.invalid/nope.json"
    result = source.binaries()
    assert result.stale is True
    assert result.from_cache is True
    assert result.data == [{"Name": "certutil.exe"}]


# --- VirusTotal: audit fields, retries, caching (mocked, no live key) ------


def test_virustotal_not_configured_has_full_audit_fields():
    result = VirusTotalSource(api_key=None).lookup_hash("a" * 64)
    assert result["status"] == "not_configured"
    assert result["indicator"] == "a" * 64
    assert result["source"] == "virustotal"
    assert result["api_outcome"] == "no_api_key"
    assert "timestamp" in result


def test_virustotal_invalid_hash_raises():
    with pytest.raises(ValueError):
        VirusTotalSource(api_key="k").lookup_hash("not-a-hash")


def test_virustotal_success_path_has_full_audit_fields_and_caches(monkeypatch, tmp_path):
    def fake_get(url, headers=None, timeout=None):
        return httpx.Response(200, json={"data": {"id": "abc"}}, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", fake_get)
    secret_key = "SECRET_API_KEY_VALUE_XYZ123"
    source = VirusTotalSource(api_key=secret_key, cache_dir=tmp_path)
    result = source.lookup_hash("a" * 64)
    assert result["status"] == "ok"
    assert result["api_outcome"] == "success"
    assert result["indicator"] == "a" * 64
    assert result["source"] == "virustotal"
    assert result["from_cache"] is False

    # Never logs/exposes the API key anywhere in the result.
    assert secret_key not in str(result)

    cached = cache_module.read_cache(tmp_path / (("a" * 64) + ".json"), ttl_seconds=3600)
    assert cached is not None
    assert cached.data == {"data": {"id": "abc"}}


def test_virustotal_cache_hit_skips_the_network(monkeypatch, tmp_path):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("must not hit the network on a cache hit")

    monkeypatch.setattr(httpx, "get", fail_if_called)
    cache_module.write_cache_atomic(tmp_path / (("b" * 64) + ".json"), {"data": {"id": "cached"}})
    source = VirusTotalSource(api_key="k", cache_dir=tmp_path)
    result = source.lookup_hash("b" * 64)
    assert result["status"] == "ok"
    assert result["api_outcome"] == "cache_hit"
    assert result["from_cache"] is True


def test_virustotal_not_found(monkeypatch):
    def fake_get(url, headers=None, timeout=None):
        return httpx.Response(404, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", fake_get)
    result = VirusTotalSource(api_key="k").lookup_hash("a" * 64)
    assert result["status"] == "not_found"
    assert result["api_outcome"] == "not_found"


def test_virustotal_rate_limited_without_cache_reports_clearly(monkeypatch):
    def always_429(url, headers=None, timeout=None):
        return httpx.Response(429, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", always_429)
    source = VirusTotalSource(api_key="k", attempts=2, sleep_fn=lambda _: None)
    result = source.lookup_hash("a" * 64)
    assert result["status"] == "unavailable"
    assert result["api_outcome"] == "rate_limited"


def test_virustotal_rate_limited_falls_back_to_stale_cache(monkeypatch, tmp_path):
    def always_429(url, headers=None, timeout=None):
        return httpx.Response(429, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", always_429)
    cache_path = tmp_path / (("c" * 64) + ".json")
    cache_module.write_cache_atomic(cache_path, {"data": {"id": "stale"}})
    source = VirusTotalSource(
        api_key="k", cache_dir=tmp_path, cache_ttl_seconds=-1, attempts=2, sleep_fn=lambda _: None
    )
    result = source.lookup_hash("c" * 64)
    assert result["status"] == "ok"
    assert result["api_outcome"] == "rate_limited_stale_cache_fallback"
    assert result["stale"] is True


def test_virustotal_retries_transient_5xx_then_succeeds(monkeypatch):
    calls = {"n": 0}

    def flaky(url, headers=None, timeout=None):
        calls["n"] += 1
        if calls["n"] < 2:
            return httpx.Response(503, request=httpx.Request("GET", url))
        return httpx.Response(200, json={"data": {"id": "ok"}}, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", flaky)
    source = VirusTotalSource(api_key="k", attempts=3, sleep_fn=lambda _: None)
    result = source.lookup_hash("a" * 64)
    assert result["status"] == "ok"
    assert calls["n"] == 2


def test_virustotal_connection_error_falls_back_to_stale_cache(monkeypatch, tmp_path):
    def always_fails(url, headers=None, timeout=None):
        raise httpx.ConnectError("boom")

    monkeypatch.setattr(httpx, "get", always_fails)
    cache_path = tmp_path / (("d" * 64) + ".json")
    cache_module.write_cache_atomic(cache_path, {"data": {"id": "stale"}})
    source = VirusTotalSource(
        api_key="k", cache_dir=tmp_path, cache_ttl_seconds=-1, attempts=2, sleep_fn=lambda _: None
    )
    result = source.lookup_hash("d" * 64)
    assert result["api_outcome"] == "error_stale_cache_fallback"
    assert result["stale"] is True


def test_virustotal_connection_error_without_cache_raises(monkeypatch):
    def always_fails(url, headers=None, timeout=None):
        raise httpx.ConnectError("boom")

    monkeypatch.setattr(httpx, "get", always_fails)
    source = VirusTotalSource(api_key="k", attempts=2, sleep_fn=lambda _: None)
    with pytest.raises(SourceError):
        source.lookup_hash("a" * 64)


# --- `intel` CLI: policy toggles are genuinely enforced ---------------------


def test_intel_disabled_sources_are_never_queried_over_the_network(monkeypatch, tmp_path):
    """Regression test for a real gap found during review: `policies/*.yaml`'s
    `sources.mitre_attack`/`lolbas`/`virustotal` fields were pydantic-validated
    but never actually read by the `intel` command or exposed by `Policy` at
    all — the same "parsed but never consulted" bug pattern found twice
    already this session (auto_apply_maximum, apply's approval_required). This
    matters specifically for VirusTotal: docs/DEFENSIVE_SECURITY.md explicitly
    warns "do not submit or query confidential, proprietary, or personal
    indicators through an unapproved public service" — an org disabling
    `sources.virustotal: false` must have that genuinely block the query, not
    just be ignored. Asserts no network call happens at all when disabled, by
    making any such call fail the test loudly rather than just checking the
    reported status.
    """
    from typer.testing import CliRunner

    from trustpatch.cli import app

    def fail_if_called(*args, **kwargs):
        raise AssertionError("a disabled source must never be queried over the network")

    monkeypatch.setattr(httpx, "get", fail_if_called)

    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("sources:\n  mitre_attack: false\n  lolbas: false\n  virustotal: false\n")
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    runner = CliRunner()
    result = runner.invoke(app, ["intel", str(project_dir), "--sha256", "a" * 64, "--policy", str(policy_file)])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["sources"]["mitre_attack"]["status"] == "disabled_by_policy"
    assert data["sources"]["lolbas"]["status"] == "disabled_by_policy"
    assert data["sources"]["virustotal"]["status"] == "disabled_by_policy"
    assert data["sources"]["virustotal"]["indicator"] == "a" * 64


@requires_network
def test_intel_enabled_sources_are_genuinely_queried(tmp_path):
    """The flip side: the default policy (all sources enabled) must still work
    end to end against the real services, through the actual CLI command."""
    from typer.testing import CliRunner

    from trustpatch.cli import app

    project_dir = tmp_path / "project"
    project_dir.mkdir()

    runner = CliRunner()
    result = runner.invoke(app, ["intel", str(project_dir), "--policy", "policies/default.yaml"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["sources"]["mitre_attack"]["status"] == "ok"
    assert data["sources"]["mitre_attack"]["technique_count"] > 100
    assert data["sources"]["lolbas"]["status"] == "ok"
    assert data["sources"]["lolbas"]["entry_count"] > 10
    assert data["sources"]["virustotal"]["status"] == "not_requested"
