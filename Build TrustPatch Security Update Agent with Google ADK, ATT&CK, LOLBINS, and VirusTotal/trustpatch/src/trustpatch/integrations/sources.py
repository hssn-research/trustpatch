from __future__ import annotations

import hashlib
import os
import random
import time as time_module
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from .. import cache as cache_module

_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class SourceError(RuntimeError):
    pass


def _request_with_retry(
    request_fn: Callable[[], httpx.Response],
    attempts: int = 3,
    base_delay: float = 0.5,
    sleep_fn: Callable[[float], None] = time_module.sleep,
) -> httpx.Response:
    """Bounded retry with exponential backoff + jitter for transient failures
    (connection errors, 429/500/502/503/504). Honors a numeric `Retry-After`
    header on 429 instead of guessing. `attempts` must be >= 1; the final
    attempt's result (success, a non-retryable status, or a raised exception)
    is always returned/raised — this never retries forever and never silently
    swallows a final failure."""
    for attempt in range(attempts):
        try:
            response = request_fn()
        except httpx.HTTPError:
            if attempt == attempts - 1:
                raise
            sleep_fn(base_delay * (2**attempt) + random.uniform(0, base_delay / 4))
            continue
        if response.status_code not in _RETRYABLE_STATUS or attempt == attempts - 1:
            return response
        retry_after = response.headers.get("Retry-After")
        delay = (
            float(retry_after)
            if retry_after and retry_after.replace(".", "", 1).isdigit()
            else base_delay * (2**attempt)
        )
        sleep_fn(delay + random.uniform(0, base_delay / 4))
    raise AssertionError("unreachable: attempts >= 1 guarantees a return or raise above")


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class SourceResult:
    """A source query result plus the evidence metadata docs/DEFENSIVE_SECURITY.md
    requires: when it was retrieved, whether it came from cache, and whether that
    cache is stale (past its TTL, served only because live retrieval failed)."""

    data: Any
    source: str
    retrieved_at: str
    from_cache: bool
    stale: bool
    extra: dict[str, Any] = field(default_factory=dict)


class JsonSource:
    def __init__(
        self,
        url: str,
        timeout: float = 10.0,
        attempts: int = 3,
        sleep_fn: Callable[[float], None] = time_module.sleep,
    ):
        self.url, self.timeout, self.attempts, self.sleep_fn = url, timeout, attempts, sleep_fn

    def get(self) -> Any:
        try:
            response = _request_with_retry(
                lambda: httpx.get(self.url, timeout=self.timeout, follow_redirects=True),
                attempts=self.attempts,
                sleep_fn=self.sleep_fn,
            )
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise SourceError(f"source unavailable: {self.url}") from exc


# Pinned release, not the moving `master` branch — see docs/DEFENSIVE_SECURITY.md:
# "replace the moving `master` URL with a pinned release". Bump deliberately; a
# newer release should be a reviewed change, not something that changes silently
# underneath every `intel` call.
DEFAULT_ATTACK_RELEASE = "v19.2"


class MitreAttackSource(JsonSource):
    """Reads a pinned ATT&CK STIX release; never treats narrative text as
    authorization. Caches the extracted techniques locally (the raw bundle is
    tens of megabytes) and records the release + retrieval timestamp with every
    result, live or cached, per docs/DEFENSIVE_SECURITY.md."""

    def __init__(
        self,
        release: str = DEFAULT_ATTACK_RELEASE,
        cache_path: Path | None = None,
        cache_ttl_seconds: float = 24 * 3600,
        **kwargs: Any,
    ):
        url = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{release}/enterprise-attack/enterprise-attack.json"
        super().__init__(url, **kwargs)
        self.release = release
        self.cache_path = cache_path
        self.cache_ttl_seconds = cache_ttl_seconds

    def techniques(self) -> SourceResult:
        cache_entry = cache_module.read_cache(self.cache_path, self.cache_ttl_seconds) if self.cache_path else None
        if cache_entry is not None and not cache_entry.stale:
            return SourceResult(
                data=cache_entry.data,
                source="mitre_attack",
                retrieved_at=cache_entry.metadata.get("retrieved_at", _now_iso()),
                from_cache=True,
                stale=False,
                extra={"release": cache_entry.metadata.get("release", self.release)},
            )
        try:
            bundle = self.get()
        except SourceError:
            if cache_entry is not None:
                return SourceResult(
                    data=cache_entry.data,
                    source="mitre_attack",
                    retrieved_at=cache_entry.metadata.get("retrieved_at", _now_iso()),
                    from_cache=True,
                    stale=True,
                    extra={"release": cache_entry.metadata.get("release", self.release), "offline_fallback": True},
                )
            raise
        techniques = [
            o for o in bundle.get("objects", []) if o.get("type") == "attack-pattern" and not o.get("revoked")
        ]
        retrieved_at = _now_iso()
        if self.cache_path:
            cache_module.write_cache_atomic(
                self.cache_path, techniques, {"release": self.release, "retrieved_at": retrieved_at}
            )
        return SourceResult(
            data=techniques,
            source="mitre_attack",
            retrieved_at=retrieved_at,
            from_cache=False,
            stale=False,
            extra={"release": self.release},
        )


class LolbasSource(JsonSource):
    """Reads the official LOLBAS static feed. Strictly validates the top-level
    shape (a malformed feed must fail loudly, never silently look like "zero
    LOLBins"), caches a last-known-good snapshot with atomic replacement, and
    falls back to that snapshot — marked stale — when the live feed is
    unreachable, per docs/DEFENSIVE_SECURITY.md."""

    def __init__(
        self,
        url: str = "https://lolbas-project.github.io/api/lolbas.json",
        cache_path: Path | None = None,
        cache_ttl_seconds: float = 24 * 3600,
        **kwargs: Any,
    ):
        super().__init__(url, **kwargs)
        self.cache_path = cache_path
        self.cache_ttl_seconds = cache_ttl_seconds

    def binaries(self) -> SourceResult:
        cache_entry = cache_module.read_cache(self.cache_path, self.cache_ttl_seconds) if self.cache_path else None
        if cache_entry is not None and not cache_entry.stale:
            return SourceResult(
                data=cache_entry.data,
                source="lolbas",
                retrieved_at=cache_entry.metadata.get("retrieved_at", _now_iso()),
                from_cache=True,
                stale=False,
            )
        try:
            raw = self.get()
            entries = self._validate(raw)
        except SourceError:
            if cache_entry is not None:
                return SourceResult(
                    data=cache_entry.data,
                    source="lolbas",
                    retrieved_at=cache_entry.metadata.get("retrieved_at", _now_iso()),
                    from_cache=True,
                    stale=True,
                    extra={"offline_fallback": True},
                )
            raise
        retrieved_at = _now_iso()
        if self.cache_path:
            cache_module.write_cache_atomic(self.cache_path, entries, {"retrieved_at": retrieved_at})
        return SourceResult(data=entries, source="lolbas", retrieved_at=retrieved_at, from_cache=False, stale=False)

    @staticmethod
    def _validate(raw: Any) -> list[dict[str, Any]]:
        if isinstance(raw, list):
            entries = raw
        elif isinstance(raw, dict) and isinstance(raw.get("entries"), list):
            entries = raw["entries"]
        else:
            raise SourceError(
                f"LOLBAS feed has an unexpected top-level shape (expected a list or "
                f"an object with an 'entries' list); got {type(raw).__name__}"
            )
        if not all(isinstance(entry, dict) for entry in entries):
            raise SourceError("LOLBAS feed entries must all be objects")
        return entries


class VirusTotalSource:
    """Optional hash-first report lookup against VirusTotal API v3. Reads
    `VIRUSTOTAL_API_KEY` only from the environment; performs no file/URL
    uploads. Every result — including `not_configured` and error paths —
    carries the indicator, a timestamp, the source name, and an explicit API
    outcome, per docs/DEFENSIVE_SECURITY.md's audit-field requirement. Bounded
    retries and 429 handling (respecting `Retry-After`) fall back to a cached
    last-known result, marked stale, rather than failing outright when one is
    available."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://www.virustotal.com/api/v3",
        cache_dir: Path | None = None,
        cache_ttl_seconds: float = 3600,
        attempts: int = 3,
        timeout: float = 10.0,
        sleep_fn: Callable[[float], None] = time_module.sleep,
    ):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url = base_url.rstrip("/")
        self.cache_dir = cache_dir
        self.cache_ttl_seconds = cache_ttl_seconds
        self.attempts = attempts
        self.timeout = timeout
        self.sleep_fn = sleep_fn

    def lookup_hash(self, sha256: str) -> dict[str, Any]:
        base = {"indicator": sha256, "source": "virustotal", "timestamp": _now_iso()}
        if not self.api_key:
            return {**base, "status": "not_configured", "api_outcome": "no_api_key"}
        if len(sha256) != 64 or any(c not in "0123456789abcdefABCDEF" for c in sha256):
            raise ValueError("invalid SHA-256")
        api_key = self.api_key

        cache_path = (self.cache_dir / f"{sha256}.json") if self.cache_dir else None
        cache_entry = cache_module.read_cache(cache_path, self.cache_ttl_seconds) if cache_path else None
        if cache_entry is not None and not cache_entry.stale:
            return {
                **base,
                "status": "ok",
                "data": cache_entry.data,
                "api_outcome": "cache_hit",
                "from_cache": True,
                "stale": False,
            }

        try:
            response = _request_with_retry(
                lambda: httpx.get(
                    f"{self.base_url}/files/{sha256}", headers={"x-apikey": api_key}, timeout=self.timeout
                ),
                attempts=self.attempts,
                sleep_fn=self.sleep_fn,
            )
        except httpx.HTTPError as exc:
            if cache_entry is not None:
                return {
                    **base,
                    "status": "ok",
                    "data": cache_entry.data,
                    "api_outcome": "error_stale_cache_fallback",
                    "from_cache": True,
                    "stale": True,
                }
            raise SourceError("VirusTotal lookup failed") from exc

        if response.status_code == 404:
            return {**base, "status": "not_found", "api_outcome": "not_found"}
        if response.status_code == 429:
            if cache_entry is not None:
                return {
                    **base,
                    "status": "ok",
                    "data": cache_entry.data,
                    "api_outcome": "rate_limited_stale_cache_fallback",
                    "from_cache": True,
                    "stale": True,
                }
            return {**base, "status": "unavailable", "api_outcome": "rate_limited"}
        try:
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise SourceError("VirusTotal lookup failed") from exc

        data = response.json()
        retrieved_at = base["timestamp"]
        if cache_path:
            cache_module.write_cache_atomic(cache_path, data, {"retrieved_at": retrieved_at})
        return {**base, "status": "ok", "data": data, "api_outcome": "success", "from_cache": False, "stale": False}


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
