from __future__ import annotations

import re

_NUMERIC_RUN = re.compile(r"\d+")


def version_key(version: str) -> tuple[int, ...]:
    """Best-effort, cross-ecosystem numeric ordering key for dotted version strings.

    Handles the common case (semver/PEP 440-style numeric releases) deterministically.
    Pre-release/build suffixes are ignored for ordering purposes, so callers that need
    exact pre-release semantics must not rely on this for correctness-critical decisions.
    """
    if version in ("*", "", None):
        return (-1,)
    core = re.split(r"[-+]", version, maxsplit=1)[0]
    parts = _NUMERIC_RUN.findall(core)
    return tuple(int(p) for p in parts) if parts else (0,)


def major_component(version: str) -> str:
    if version in ("*", "", None):
        return "*"
    return version.lstrip("v").split(".")[0]


def is_major_change(current: str, proposed: str) -> bool:
    return major_component(current) != major_component(proposed)


def classify_bump(current: str, proposed: str) -> str:
    """Classify a version change as major/minor/patch/equal/unknown."""
    a, b = version_key(current), version_key(proposed)
    if a == b:
        return "equal"
    if a[:1] == (-1,) or b[:1] == (-1,):
        return "unknown"
    length = max(len(a), len(b))
    a = a + (0,) * (length - len(a))
    b = b + (0,) * (length - len(b))
    if a[0] != b[0]:
        return "major"
    if length > 1 and a[1] != b[1]:
        return "minor"
    return "patch"
