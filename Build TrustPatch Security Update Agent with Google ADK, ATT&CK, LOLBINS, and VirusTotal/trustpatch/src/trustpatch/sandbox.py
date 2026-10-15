from __future__ import annotations

import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path


class SandboxError(RuntimeError):
    pass


@dataclass
class Sandbox:
    root: Path
    worktree: Path
    base_commit: str

    def cleanup(self) -> None:
        subprocess.run(
            ["git", "-C", str(self.root), "worktree", "remove", "--force", str(self.worktree)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        shutil.rmtree(self.worktree, ignore_errors=True)


def _run(args: list[str], cwd: Path | None = None, timeout: float = 30) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=True)
    except FileNotFoundError as exc:
        raise SandboxError("git is not installed; disposable worktree isolation is unavailable") from exc
    except subprocess.CalledProcessError as exc:
        raise SandboxError(f"{' '.join(args)} failed: {exc.stderr.strip()}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SandboxError(f"{' '.join(args)} timed out") from exc


def create(root: Path, update_id: str, base_dir: Path | None = None) -> Sandbox:
    """Create a disposable git worktree, detached at HEAD, for isolated preparation
    of a single candidate update.

    Fails closed (raises SandboxError) if `root` is not a git repository, has no
    commits, or git is unavailable. TrustPatch never falls back to mutating the
    primary tree directly when isolation cannot be established. The worktree is
    checked out from the last commit, never from uncommitted working-tree changes,
    so in-progress user edits are never exposed to untrusted package/build scripts.
    """
    head = _run(["git", "-C", str(root), "rev-parse", "HEAD"], timeout=10).stdout.strip()
    base = base_dir or Path(tempfile.gettempdir()) / "trustpatch-sandbox"
    base.mkdir(parents=True, exist_ok=True)
    worktree = base / f"{update_id}-{uuid.uuid4().hex[:8]}"
    _run(["git", "-C", str(root), "worktree", "add", "--detach", str(worktree), head], timeout=30)
    return Sandbox(root=root, worktree=worktree, base_commit=head)


def changed_files(sandbox: Sandbox) -> list[str]:
    """Independently list files that differ between the worktree and its base
    commit, including untracked files. Used by the verifier to compare actual vs
    expected changes — never trust the executor's own report of what it changed."""
    result = _run(
        ["git", "-C", str(sandbox.worktree), "diff", "--name-only", sandbox.base_commit],
        timeout=15,
    )
    tracked = {line.strip() for line in result.stdout.splitlines() if line.strip()}
    untracked = _run(
        ["git", "-C", str(sandbox.worktree), "ls-files", "--others", "--exclude-standard"],
        timeout=15,
    )
    tracked.update(line.strip() for line in untracked.stdout.splitlines() if line.strip())
    return sorted(tracked)
