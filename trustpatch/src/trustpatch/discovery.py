from __future__ import annotations

import json
import re
import subprocess
import tomllib
from pathlib import Path
from typing import Any

from .models import Dependency, Manifest


def git_root(path: Path) -> Path | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        return Path(result.stdout.strip())
    except (subprocess.SubprocessError, FileNotFoundError):
        return None


def detect_manifests(root: Path) -> list[Manifest]:
    found: list[Manifest] = []
    if (root / "pyproject.toml").exists() or (root / "requirements.txt").exists():
        path = "pyproject.toml" if (root / "pyproject.toml").exists() else "requirements.txt"
        lock = next(
            (p.name for p in (root / "uv.lock", root / "poetry.lock", root / "Pipfile.lock") if p.exists()), None
        )
        found.append(Manifest("python", path, lock, "uv/poetry/pip"))
    if (root / "package.json").exists():
        lock = next(
            (p.name for p in (root / "pnpm-lock.yaml", root / "yarn.lock", root / "package-lock.json") if p.exists()),
            None,
        )
        found.append(Manifest("node", "package.json", lock, "pnpm/yarn/npm"))
    if (root / "go.mod").exists():
        found.append(Manifest("go", "go.mod", "go.sum" if (root / "go.sum").exists() else None, "go"))
    if (root / "Cargo.toml").exists():
        found.append(Manifest("rust", "Cargo.toml", "Cargo.lock" if (root / "Cargo.lock").exists() else None, "cargo"))
    return found


def _version(value: Any) -> str:
    return re.sub(r"^[~^<>= ]+", "", str(value)).split(",")[0]


def inventory(root: Path, manifests: list[Manifest] | None = None) -> list[Dependency]:
    manifests = manifests or detect_manifests(root)
    deps: list[Dependency] = []
    for manifest in manifests:
        source = manifest.lockfile or manifest.path
        if manifest.ecosystem == "python" and manifest.path == "pyproject.toml":
            data = tomllib.loads((root / manifest.path).read_text())
            project = data.get("project", {})
            for item in project.get("dependencies", []):
                if not isinstance(item, str):
                    continue
                pkg = re.split(r"[<>=!~; ]", item, maxsplit=1)[0]
                deps.append(Dependency(pkg, _version(item[len(pkg) :] or "*"), "python", True, "runtime", source))
            for group in project.get("optional-dependencies", {}).values():
                for item in group:
                    if not isinstance(item, str):
                        continue
                    pkg = re.split(r"[<>=!~; ]", item, maxsplit=1)[0]
                    deps.append(
                        Dependency(pkg, _version(item[len(pkg) :] or "*"), "python", True, "development", source)
                    )
        elif manifest.ecosystem == "python" and manifest.path == "requirements.txt":
            for line in (root / manifest.path).read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = re.split(r"[<>=!~; ]", line, maxsplit=1)
                    deps.append(
                        Dependency(parts[0], _version(line[len(parts[0]) :] or "*"), "python", True, "runtime", source)
                    )
        elif manifest.ecosystem == "node":
            data = json.loads((root / manifest.path).read_text())
            for scope, section in (
                ("runtime", "dependencies"),
                ("development", "devDependencies"),
                ("optional", "optionalDependencies"),
            ):
                for name, value in data.get(section, {}).items():
                    deps.append(Dependency(name, _version(value), "node", True, scope, source))
        elif manifest.ecosystem == "go":
            deps.extend(_parse_go_mod((root / manifest.path).read_text(), source))
        elif manifest.ecosystem == "rust":
            data = tomllib.loads((root / manifest.path).read_text())
            for scope, section in (
                ("runtime", "dependencies"),
                ("development", "dev-dependencies"),
                ("build", "build-dependencies"),
            ):
                for name, value in data.get(section, {}).items():
                    version = value.get("version", "*") if isinstance(value, dict) else value
                    deps.append(Dependency(name, _version(version), "rust", True, scope, source))
    return deps


def _parse_go_mod(text: str, source: str) -> list[Dependency]:
    deps: list[Dependency] = []
    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("require (") and stripped.endswith("("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        if in_block:
            entry = stripped
        elif stripped.startswith("require "):
            entry = stripped[len("require ") :]
        else:
            continue
        indirect = "// indirect" in entry
        entry = entry.split("//")[0].strip()
        parts = entry.split()
        if len(parts) < 2:
            continue
        name, version = parts[0], parts[1]
        deps.append(Dependency(name, version.lstrip("v"), "go", not indirect, "runtime", source))
    return deps
