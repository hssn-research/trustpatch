from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class CacheEntry:
    data: Any
    cached_at: float
    age_seconds: float
    stale: bool
    metadata: dict[str, Any]


def read_cache(path: Path, ttl_seconds: float) -> CacheEntry | None:
    """Read a last-known-good snapshot written by `write_cache_atomic`.

    Returns None only when there is no readable cache at all (missing or
    corrupt file) — a caller must treat that as "no fallback available", not
    as "up to date". A present-but-expired cache is still returned, with
    `stale=True`, so a caller can use it as an offline/degraded fallback while
    honestly reporting that it's stale (see docs/DEFENSIVE_SECURITY.md's LOLBAS
    and VirusTotal "stale-data indicator" / "stale-result handling" requirements).
    """
    try:
        record = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    cached_at = record.get("cached_at")
    if not isinstance(cached_at, int | float):
        return None
    age = time.time() - cached_at
    metadata = {k: v for k, v in record.items() if k not in ("data", "cached_at")}
    return CacheEntry(
        data=record.get("data"), cached_at=cached_at, age_seconds=age, stale=age > ttl_seconds, metadata=metadata
    )


def write_cache_atomic(path: Path, data: Any, metadata: dict[str, Any] | None = None) -> None:
    """Write a cache snapshot via write-to-temp-then-rename, so a reader never
    observes a partially-written file (os.replace is atomic on POSIX within the
    same filesystem — the temp file is created in the same directory)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    record: dict[str, Any] = {"cached_at": time.time(), "data": data, **(metadata or {})}
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(record, handle)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
