from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import httpx

from ..models import Advisory
from ..versions import version_key
from .sources import SourceError, _request_with_retry

ECOSYSTEM_MAP = {"python": "PyPI", "node": "npm", "go": "Go", "rust": "crates.io"}


class OsvSource:
    """Read-only OSV.dev advisory lookup. Never authoritative for approval.

    Uses the same bounded-retry-with-backoff helper as the ATT&CK/LOLBAS/
    VirusTotal adapters (docs/TODO.md Phase 3: "Add retry/backoff") so a
    single transient network blip does not downgrade a dependency straight to
    `unassessed` — a failure that still happens, correctly, once retries are
    exhausted (fail-closed, never treated as "clean")."""

    def __init__(
        self,
        base_url: str = "https://api.osv.dev/v1",
        timeout: float = 10.0,
        attempts: int = 3,
        sleep_fn: Callable[[float], None] = time.sleep,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.attempts = attempts
        self.sleep_fn = sleep_fn

    def query(self, name: str, version: str, ecosystem: str) -> list[dict[str, Any]]:
        osv_ecosystem = ECOSYSTEM_MAP.get(ecosystem)
        if not osv_ecosystem or version in ("*", ""):
            return []
        payload = {"package": {"name": name, "ecosystem": osv_ecosystem}, "version": version}
        try:
            response = _request_with_retry(
                lambda: httpx.post(f"{self.base_url}/query", json=payload, timeout=self.timeout),
                attempts=self.attempts,
                sleep_fn=self.sleep_fn,
            )
            response.raise_for_status()
            return response.json().get("vulns", [])
        except (httpx.HTTPError, ValueError) as exc:
            raise SourceError(f"OSV query failed for {name}@{version}") from exc


def normalize(raw: dict[str, Any], name: str, ecosystem: str) -> Advisory:
    """Convert a raw OSV vulnerability record into a normalized Advisory."""
    osv_ecosystem = ECOSYSTEM_MAP.get(ecosystem)
    fixed_versions: set[str] = set()
    affected_range = None
    for affected in raw.get("affected", []):
        package = affected.get("package", {})
        if package.get("ecosystem") != osv_ecosystem or package.get("name") != name:
            continue
        for rng in affected.get("ranges", []):
            introduced = None
            for event in rng.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    fixed_versions.add(event["fixed"])
                    if affected_range is None:
                        lower = introduced or "0"
                        affected_range = f">={lower},<{event['fixed']}"
        for version in affected.get("versions", []):
            if version == name:
                continue

    severity = "unknown"
    for entry in raw.get("severity", []):
        if entry.get("type") == "CVSS_V3":
            severity = f"CVSS_V3:{entry.get('score')}"
            break
    else:
        db_specific = raw.get("database_specific", {})
        if isinstance(db_specific, dict) and db_specific.get("severity"):
            severity = str(db_specific["severity"]).lower()

    evidence_url = None
    for ref in raw.get("references", []):
        if ref.get("url"):
            evidence_url = ref["url"]
            break
    if evidence_url is None:
        evidence_url = f"https://osv.dev/vulnerability/{raw.get('id')}"

    return Advisory(
        id=raw.get("id", "UNKNOWN"),
        summary=(raw.get("summary") or raw.get("details") or "").strip()[:500],
        severity=severity,
        affected_range=affected_range,
        fixed_versions=sorted(fixed_versions, key=version_key),
        source="osv.dev",
        evidence_url=evidence_url,
    )


def minimal_fixed_version(advisories: list[Advisory], current: str) -> str | None:
    """Smallest fixed version at/above `current` that satisfies every advisory, or None if unresolved."""
    current_key = version_key(current)
    candidates: set[str] = set()
    for advisory in advisories:
        candidates.update(advisory.fixed_versions)
    eligible = sorted((v for v in candidates if version_key(v) >= current_key), key=version_key)
    for candidate in eligible:
        candidate_key = version_key(candidate)
        if all(any(version_key(fv) <= candidate_key for fv in a.fixed_versions) for a in advisories):
            return candidate
    return None
