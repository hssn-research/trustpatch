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
        result = subprocess.run(["git", "-C", str(path), "rev-parse", "--show-toplevel"], capture_output=True, text=True, timeout=5, check=True)
        return Path(result.stdout.strip())
    except (subprocess.SubprocessError, FileNotFoundError):
        return None


def detect_manifests(root: Path) -> list[Manifest]:
    found: list[Manifest] = []
    if (root / "pyproject.toml").exists() or (root / "requirements.txt").exists():
        path = "pyproject.toml" if (root / "pyproject.toml").exists() else "requirements.txt"
        lock = next((p.name for p in (root / "uv.lock", root / "poetry.lock", root / "Pipfile.lock") if p.exists()), None)
        found.append(Manifest("python", path, lock, "uv/poetry/pip"))
    if (root / "package.json").exists():
        lock = next((p.name for p in (root / "pnpm-lock.yaml", root / "yarn.lock", root / "package-lock.json") if p.exists()), None)
        found.append(Manifest("node", "package.json", lock, "pnpm/yarn/npm"))
    if (root / "go.mod").exists(): found.append(Manifest("go", "go.mod", "go.sum" if (root / "go.sum").exists() else None, "go"))
    if (root / "Cargo.toml").exists(): found.append(Manifest("rust", "Cargo.toml", "Cargo.lock" if (root / "Cargo.lock").exists() else None, "cargo"))
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
            for name, value in {x: "*" for x in project.get("dependencies", []) if isinstance(x, str)}.items():
                pkg = re.split(r"[<>=!~; ]", name, maxsplit=1)[0]
                deps.append(Dependency(pkg, _version(value), "python", True, "runtime", source))
            for group in data.get("project", {}).get("optional-dependencies", {}).values():
                for item in group:
                    pkg = re.split(r"[<>=!~; ]", item, maxsplit=1)[0]
                    deps.append(Dependency(pkg, "*", "python", True, "development", source))
        elif manifest.ecosystem == "python" and manifest.path == "requirements.txt":
            for line in (root / manifest.path).read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = re.split(r"[<>=!~; ]", line, maxsplit=1)
                    deps.append(Dependency(parts[0], _version(line[len(parts[0]):] or "*"), "python", True, "runtime", source))
        elif manifest.ecosystem == "node":
            data = json.loads((root / manifest.path).read_text())
            for scope, section in (("runtime", "dependencies"), ("development", "devDependencies"), ("optional", "optionalDependencies")):
                for name, value in data.get(section, {}).items(): deps.append(Dependency(name, _version(value), "node", True, scope, source))
    return deps
