from __future__ import annotations

import httpx


def latest_version(name: str, ecosystem: str, timeout: float = 10.0) -> str | None:
    """Best-effort lookup of the latest published version. Returns None when the
    ecosystem is unsupported or the registry cannot be reached (never raises for
    "unknown" — callers must treat None as "no outdated-version evidence available",
    not as "up to date").
    """
    try:
        if ecosystem == "python":
            response = httpx.get(f"https://pypi.org/pypi/{name}/json", timeout=timeout, follow_redirects=True)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json().get("info", {}).get("version")
        if ecosystem == "node":
            response = httpx.get(f"https://registry.npmjs.org/{name}/latest", timeout=timeout, follow_redirects=True)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json().get("version")
    except (httpx.HTTPError, ValueError):
        return None
    return None
