from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Candidate


class ExecutorError(RuntimeError):
    pass


_EDITABLE_MANIFEST_NAMES: dict[str, tuple[str, ...]] = {
    "node": ("package.json",),
    "python": ("pyproject.toml", "requirements.txt"),
}


def _find_manifest_source(candidate: Candidate) -> str:
    """Find the human-editable manifest to edit for this ecosystem.

    `Dependency.source` is *not* this: discovery.py sets it to the lockfile name
    when a lockfile is present (it records dependency *provenance*, for audit and
    SBOM purposes), so for any project with a lockfile it would point at
    package-lock.json/uv.lock/etc rather than the manifest. The manifest to edit
    is instead looked up in `candidate.expected_files`, which the planner always
    populates with the manifest path for the dependency's ecosystem.
    """
    dep = candidate.dependency
    candidates = _EDITABLE_MANIFEST_NAMES.get(dep.ecosystem, ())
    for file in candidate.expected_files:
        if Path(file).name in candidates:
            return file
    raise ExecutorError(
        f"no editable manifest for ecosystem {dep.ecosystem!r} found in expected_files {candidate.expected_files}"
    )


def apply_manifest_update(worktree: Path, candidate: Candidate) -> list[str]:
    """Apply only the planned dependency version change to its source manifest,
    as plain text/JSON editing. Never executes package-manager or build scripts;
    lockfiles are intentionally left untouched here (see docs/DESIGN.md) — a
    verifier must treat a stale lockfile as a blocking finding, not a silent pass.
    Returns the list of files this step wrote (relative to `worktree`)."""
    dep = candidate.dependency
    manifest_source = _find_manifest_source(candidate)
    manifest_path = worktree / manifest_source
    if not manifest_path.exists():
        raise ExecutorError(f"manifest not found in worktree: {manifest_source}")

    if dep.ecosystem == "node" and manifest_path.name == "package.json":
        data = json.loads(manifest_path.read_text())
        changed = False
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            if dep.name in data.get(section, {}):
                data[section][dep.name] = candidate.proposed_version
                changed = True
        if not changed:
            raise ExecutorError(f"{dep.name} not found in {manifest_source}")
        manifest_path.write_text(json.dumps(data, indent=2) + "\n")
        return [manifest_source]

    if dep.ecosystem == "python" and manifest_path.name == "requirements.txt":
        lines = manifest_path.read_text().splitlines()
        name_pattern = re.compile(rf"^\s*{re.escape(dep.name)}(\[[^\]]*\])?\s*[<>=!~;]")
        updated = False
        for i, line in enumerate(lines):
            if not name_pattern.match(line):
                continue
            if "--hash" in line:
                raise ExecutorError(
                    f"{dep.name} is hash-pinned in {manifest_source}; refusing to rewrite it automatically "
                    "because the new version's hash cannot be verified without running the package manager"
                )
            code, _, comment = line.partition("#")
            code = code.rstrip()
            op_match = re.search(r"[<>=!~]", code)
            semicolon_index = code.find(";")
            if op_match is None or (semicolon_index != -1 and semicolon_index < op_match.start()):
                raise ExecutorError(
                    f"{dep.name} has no simple version specifier in {manifest_source} that trustpatch can rewrite "
                    "(unpinned, or the version operator only appears inside an environment marker)"
                )
            name_part, rest = code[: op_match.start()], code[op_match.start() :]
            specifier, _, marker = rest.partition(";")
            if "," in specifier:
                raise ExecutorError(
                    f"{dep.name} has a compound version constraint in {manifest_source} "
                    f"({specifier.strip()!r}); refusing to guess which bound to change"
                )
            new_line = f"{name_part.strip()}=={candidate.proposed_version}"
            if marker.strip():
                new_line += f"; {marker.strip()}"
            if comment.strip():
                new_line += f"  #{comment}"
            lines[i] = new_line
            updated = True
        if not updated:
            raise ExecutorError(f"{dep.name} not found in {manifest_source}")
        manifest_path.write_text("\n".join(lines) + "\n")
        return [manifest_source]

    if dep.ecosystem == "python" and manifest_path.name == "pyproject.toml":
        text = manifest_path.read_text()
        find_pattern = re.compile(rf'"{re.escape(dep.name)}(?:\[[^\]]*\])?\s*[<>=!~][^"]*"')
        match = find_pattern.search(text)
        if match is None:
            raise ExecutorError(f"{dep.name} not found as a pinned dependency in {manifest_source}")
        original = match.group(0)
        inner = original[1:-1]
        name_part, specifier = re.split(r"(?=[<>=!~])", inner, maxsplit=1)
        version_part, _, marker = specifier.partition(";")
        if "," in version_part:
            raise ExecutorError(
                f"{dep.name} has a compound version constraint in {manifest_source} "
                f"({version_part.strip()!r}); refusing to guess which bound to change"
            )
        replacement = f'"{name_part}>={candidate.proposed_version}'
        if marker.strip():
            replacement += f"; {marker.strip()}"
        replacement += '"'
        manifest_path.write_text(text.replace(original, replacement, 1))
        return [manifest_source]

    raise ExecutorError(f"no manifest editor implemented for {dep.ecosystem}:{manifest_path.name}")
