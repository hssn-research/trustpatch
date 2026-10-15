import shutil
import sys

import pytest

from trustpatch.checks import ResourceLimits, minimal_env, run_all, run_check
from trustpatch.checks import resource as _resource_module

requires_resource_module = pytest.mark.skipif(_resource_module is None, reason="resource module is POSIX-only")
requires_bwrap = pytest.mark.skipif(shutil.which("bwrap") is None, reason="bwrap is required for network isolation")


def test_run_check_passes_on_success(tmp_path):
    result = run_check("test", [sys.executable, "-c", "print('ok')"], tmp_path)
    assert result.passed is True
    assert result.returncode == 0
    assert "ok" in result.stdout


def test_run_check_fails_on_nonzero_exit(tmp_path):
    result = run_check("test", [sys.executable, "-c", "import sys; sys.exit(1)"], tmp_path)
    assert result.passed is False
    assert result.returncode == 1


def test_run_check_times_out(tmp_path):
    result = run_check("test", [sys.executable, "-c", "import time; time.sleep(5)"], tmp_path, timeout=0.2)
    assert result.passed is False
    assert result.timed_out is True


def test_run_check_missing_command_does_not_raise(tmp_path):
    # With network isolation (default), the immediate child is bwrap, which
    # exists — a missing *inner* command surfaces as a nonzero exit + stderr
    # rather than Python's FileNotFoundError. Both are valid failure reports;
    # this must never raise either way.
    result = run_check("test", ["definitely-not-a-real-command-xyz"], tmp_path)
    assert result.passed is False
    assert result.error is not None or result.returncode != 0


def test_run_check_missing_command_without_network_isolation_sets_error(tmp_path):
    result = run_check("test", ["definitely-not-a-real-command-xyz"], tmp_path, isolate_network=False)
    assert result.passed is False
    assert result.error is not None


def test_minimal_env_scrubs_credentials(monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "leaked")
    monkeypatch.setenv("GITHUB_TOKEN", "leaked")
    monkeypatch.setenv("SSH_AUTH_SOCK", "leaked")
    env = minimal_env()
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "GITHUB_TOKEN" not in env
    assert "SSH_AUTH_SOCK" not in env


def test_minimal_env_is_actually_applied_to_subprocess(tmp_path, monkeypatch):
    monkeypatch.setenv("SUPER_SECRET_TOKEN", "should-not-leak")
    result = run_check(
        "test",
        [sys.executable, "-c", "import os; print(os.environ.get('SUPER_SECRET_TOKEN', 'ABSENT'))"],
        tmp_path,
    )
    assert "ABSENT" in result.stdout
    assert "should-not-leak" not in result.stdout


def test_run_all_flattens_categories(tmp_path):
    checks = {
        "test": [[sys.executable, "-c", "print(1)"]],
        "build": [[sys.executable, "-c", "print(2)"], [sys.executable, "-c", "import sys; sys.exit(1)"]],
    }
    results = run_all(checks, tmp_path)
    assert len(results) == 3
    assert sum(1 for r in results if r.passed) == 2


def test_default_limits_do_not_break_normal_interpreter_startup(tmp_path):
    result = run_check("test", [sys.executable, "-c", "print('still works')"], tmp_path)
    assert result.passed is True
    assert "still works" in result.stdout


@requires_resource_module
def test_cpu_limit_kills_a_busy_loop(tmp_path):
    busy_loop = "x = 0\nwhile True:\n    x += 1\n"
    result = run_check(
        "test",
        [sys.executable, "-c", busy_loop],
        tmp_path,
        timeout=15,
        limits=ResourceLimits(cpu_seconds=1, memory_bytes=None, max_processes=None),
    )
    assert result.passed is False
    assert result.timed_out is False, "should be killed by the CPU rlimit, not the wall-clock timeout"


@requires_resource_module
def test_memory_limit_kills_an_over_allocation(tmp_path):
    allocate_too_much = "b = bytearray(500 * 1024 * 1024)\nprint(len(b))"
    result = run_check(
        "test",
        [sys.executable, "-c", allocate_too_much],
        tmp_path,
        limits=ResourceLimits(cpu_seconds=None, memory_bytes=100 * 1024 * 1024, max_processes=None),
    )
    assert result.passed is False


def test_limits_none_disables_resource_limiting(tmp_path):
    result = run_check("test", [sys.executable, "-c", "print('unlimited')"], tmp_path, limits=None)
    assert result.passed is True


_NETWORK_PROBE = (
    "import socket, urllib.request\n"
    "try:\n"
    "    urllib.request.urlopen('https://pypi.org', timeout=5)\n"
    "    print('REACHED')\n"
    "except Exception as e:\n"
    "    print('BLOCKED', type(e).__name__)\n"
)


@requires_bwrap
def test_isolate_network_true_actually_blocks_network_access(tmp_path):
    result = run_check("test", [sys.executable, "-c", _NETWORK_PROBE], tmp_path, isolate_network=True)
    assert result.network_isolated is True
    assert "BLOCKED" in result.stdout
    assert "REACHED" not in result.stdout


def test_isolate_network_false_reports_not_isolated(tmp_path):
    result = run_check("test", [sys.executable, "-c", "print('x')"], tmp_path, isolate_network=False)
    assert result.network_isolated is False


def test_network_isolated_field_is_honest_when_bwrap_missing(tmp_path, monkeypatch):
    monkeypatch.setattr("trustpatch.checks.shutil.which", lambda name: None)
    result = run_check("test", [sys.executable, "-c", "print('x')"], tmp_path, isolate_network=True)
    assert result.network_isolated is False
    assert result.passed is True
