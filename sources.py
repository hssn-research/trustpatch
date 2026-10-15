from __future__ import annotations

import hashlib
import os
from typing import Any

import httpx


class SourceError(RuntimeError):
    pass


class JsonSource:
    def __init__(self, url: str, timeout: float = 10.0):
        self.url, self.timeout = url, timeout

    def get(self) -> Any:
        try:
            response = httpx.get(self.url, timeout=self.timeout, follow_redirects=True)
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise SourceError(f"source unavailable: {self.url}") from exc


class MitreAttackSource(JsonSource):
    """Reads ATT&CK STIX bundles; never treats narrative text as authorization."""

    def __init__(
        self,
        url: str = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    ):
        super().__init__(url)

    def techniques(self) -> list[dict[str, Any]]:
        bundle = self.get()
        return [o for o in bundle.get("objects", []) if o.get("type") == "attack-pattern" and not o.get("revoked")]


class LolbasSource(JsonSource):
    def __init__(self, url: str = "https://lolbas-project.github.io/api/lolbas.json"):
        super().__init__(url)

    def binaries(self) -> list[dict[str, Any]]:
        data = self.get()
        return data if isinstance(data, list) else data.get("entries", data if isinstance(data, list) else [])


class VirusTotalSource:
    def __init__(self, api_key: str | None = None, base_url: str = "https://www.virustotal.com/api/v3"):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url = base_url.rstrip("/")

    def lookup_hash(self, sha256: str) -> dict[str, Any]:
        if not self.api_key:
            return {"status": "not_configured", "sha256": sha256}
        if len(sha256) != 64 or any(c not in "0123456789abcdefABCDEF" for c in sha256):
            raise ValueError("invalid SHA-256")
        try:
            response = httpx.get(f"{self.base_url}/files/{sha256}", headers={"x-apikey": self.api_key}, timeout=10)
            if response.status_code == 404:
                return {"status": "not_found", "sha256": sha256}
            response.raise_for_status()
            return {"status": "ok", "data": response.json()}
        except httpx.HTTPError as exc:
            raise SourceError("VirusTotal lookup failed") from exc


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
