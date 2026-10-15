from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

try:
    import resource
except ImportError:  # pragma: no cover - resource is POSIX-only
    resource = None  # type: ignore[assignment]

_ENV_ALLOWLIST = {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TZ"}


def _bwrap_path() -> str | None:
    """`bubblewrap` (bwrap) provides genuine unprivileged network-namespace
    isolation (--unshare-net) — unlike a bare `unshare --net`, it works even
    where AppArmor restricts unprivileged user-namespace creation (Ubuntu
    24.04+), because distros ship a dedicated AppArmor policy allowlisting the
    bwrap binary specifically. When unavailable, checks fall back to running
    without network isolation and `CheckResult.network_isolated` reports that
    honestly — never claim SR-003 isolation that wasn't actually applied."""
    return shutil.which("bwrap")


def _wrap_for_network_isolation(command: list[str], cwd: Path, bwrap: str) -> list[str]:
    cwd_str = str(cwd)
    return [
        bwrap,
        "--die-with-parent",
        "--unshare-net",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
        "--bind",
        cwd_str,
        cwd_str,
        "--chdir",
        cwd_str,
        "--",
        *command,
    ]


@dataclass(frozen=True)
class ResourceLimits:
    """Unprivileged process resource limits (no root required — a process may
    always lower its own rlimits via `setrlimit`). This is a backstop against
    runaway checks (fork bombs, memory leaks, CPU spins), not a security sandbox:
    it does not isolate the check from other processes owned by the same user,
    and RLIMIT_NPROC counts against the user's total process count system-wide,
    not just this check's descendants. Defaults are generous enough for typical
    interpreters (python/node/etc.) to run normally."""

    cpu_seconds: int | None = 120
    memory_bytes: int | None = 2 * 1024 * 1024 * 1024
    max_processes: int | None = 256


def _apply_resource_limits(limits: ResourceLimits, skip_nproc: bool = False) -> Callable[[], None]:
    """`skip_nproc` must be true when the wrapped command is `bwrap`: the kernel
    charges `unshare(CLONE_NEWUSER)` (which bwrap's network isolation needs)
    against the calling process's RLIMIT_NPROC ucounts, and this is *not* a
    simple "how many processes has this command spawned" check — it reliably
    fails namespace creation at surprisingly high limits (confirmed: 500 fails,
    1000 succeeds) and the exact threshold depends on other processes already
    owned by the same user elsewhere on the system. A backstop that
    unpredictably breaks the isolation it's meant to complement is worse than
    no backstop, so NPROC is skipped whenever bwrap is in the command line;
    CPU and memory limits are unaffected and still applied.
    """

    def _set() -> None:
        if resource is None:
            return
        if limits.cpu_seconds is not None:
            resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
        if limits.memory_bytes is not None:
            resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
        if limits.max_processes is not None and not skip_nproc:
            resource.setrlimit(resource.RLIMIT_NPROC, (limits.max_processes, limits.max_processes))

    return _set


def minimal_env() -> dict[str, str]:
    """A scrubbed environment for untrusted checks: no cloud/SSH/CI credentials,
    no tokens, no production secrets — only what's needed to locate an interpreter.
    This mitigates credential exposure (SR-002) but is not a substitute for real
    OS-level sandboxing (network namespaces, cgroups); see checks.run_check."""
    return {k: v for k, v in os.environ.items() if k in _ENV_ALLOWLIST}


@dataclass
class CheckResult:
    category: str
    command: list[str]
    returncode: int
    passed: bool
    stdout: str
    stderr: str
    timed_out: bool = False
    error: str | None = None
    network_isolated: bool = False


def run_check(
    category: str,
    command: list[str],
    cwd: Path,
    timeout: float = 300,
    limits: ResourceLimits | None = ResourceLimits(),
    isolate_network: bool = True,
) -> CheckResult:
    """Run one configured command (argv list, never a shell string) inside the
    isolated worktree with a scrubbed environment, a hard wall-clock timeout,
    (on POSIX) CPU/memory/process-count rlimits applied to the child before exec,
    and — when `isolate_network` is true and `bwrap` (bubblewrap) is installed —
    a real network namespace with no network access at all (SR-003).

    KNOWN LIMITATION: this provides filesystem isolation (via the sandbox worktree),
    credential-environment scrubbing, unprivileged resource backstops, and network
    isolation when bwrap is available, but no cgroup-based disk-I/O isolation.
    `CheckResult.network_isolated` always reflects what actually happened — pass
    `isolate_network=False` or `limits=None` to opt out explicitly.
    """
    bwrap = _bwrap_path() if isolate_network else None
    effective_command = _wrap_for_network_isolation(command, cwd, bwrap) if bwrap else command
    preexec_fn = (
        _apply_resource_limits(limits, skip_nproc=bwrap is not None)
        if limits is not None and resource is not None
        else None
    )
    try:
        result = subprocess.run(
            effective_command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=minimal_env(),
            check=False,
            preexec_fn=preexec_fn,
        )
        return CheckResult(
            category,
            command,
            result.returncode,
            result.returncode == 0,
            result.stdout[-8000:],
            result.stderr[-8000:],
            network_isolated=bwrap is not None,
        )
    except subprocess.TimeoutExpired:
        return CheckResult(category, command, -1, False, "", "", timed_out=True, error="timed out")
    except FileNotFoundError as exc:
        return CheckResult(category, command, -1, False, "", "", error=str(exc))


def run_all(
    checks: dict[str, list[list[str]]],
    cwd: Path,
    timeout: float = 300,
    limits: ResourceLimits | None = ResourceLimits(),
    isolate_network: bool = True,
) -> list[CheckResult]:
    results: list[CheckResult] = []
    for category, commands in checks.items():
        for command in commands:
            results.append(run_check(category, command, cwd, timeout, limits, isolate_network))
    return results
