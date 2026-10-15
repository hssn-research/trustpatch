"""Coverage for the optional Google ADK surface (src/trustpatch/adk_agent.py).

Before this test existed, nothing imported trustpatch.adk_agent at all: not the
CLI, not any other test. A real syntax error (`return {.` instead of `return {`)
sat in this file undetected — it would have crashed on the very first import by
anyone who installed the `adk` extra. mypy/ruff should catch that too, but a
stale cache can mask it (as happened here), so a real test that imports the
module is the only check that is not dependent on cache freshness.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

import trustpatch.adk_agent as adk_agent_module


def test_build_agent_raises_a_clear_error_when_adk_is_not_installed():
    """google-adk is an optional extra (pyproject.toml `[project.optional-dependencies].adk`)
    and is not installed in this environment. build_agent() must fail with a clear,
    actionable error rather than a bare ImportError traceback."""
    with pytest.raises(RuntimeError, match="adk"):
        adk_agent_module.build_agent()


def test_inspect_project_tool_returns_deterministic_facts_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Simulate google-adk being installed (without requiring the real, heavy
    dependency) to exercise the actual tool function build_agent() wires up.
    Confirms SR-008 (LLM isolation): the agent's only tool is a read-only
    wrapper around discovery.detect_manifests/inventory, and the instruction
    text keeps the LLM non-authoritative."""
    captured: dict = {}

    class FakeAgent:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    fake_agents_module = types.ModuleType("google.adk.agents")
    fake_agents_module.Agent = FakeAgent  # type: ignore[attr-defined]
    fake_adk_module = types.ModuleType("google.adk")
    fake_adk_module.agents = fake_agents_module  # type: ignore[attr-defined]
    fake_google_module = sys.modules.get("google") or types.ModuleType("google")
    fake_google_module.adk = fake_adk_module  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "google", fake_google_module)
    monkeypatch.setitem(sys.modules, "google.adk", fake_adk_module)
    monkeypatch.setitem(sys.modules, "google.adk.agents", fake_agents_module)

    agent = adk_agent_module.build_agent()
    assert isinstance(agent, FakeAgent)

    instruction = captured["instruction"].lower()
    assert "never authorize" in instruction
    assert "never" in instruction and "claim scans" in instruction

    assert len(captured["tools"]) == 1
    inspect_project = captured["tools"][0]

    (tmp_path / "package.json").write_text('{"dependencies": {"left-pad": "1.0.0"}}')
    result = inspect_project(str(tmp_path))

    assert result == {
        "manifests": [m.__dict__ for m in adk_agent_module.detect_manifests(tmp_path)],
        "dependencies": [d.__dict__ for d in adk_agent_module.inventory(tmp_path)],
    }
    assert result["dependencies"][0]["name"] == "left-pad"
    # The tool must never return anything beyond deterministic project facts
    # (no approval/policy/credential fields) — this is the entire LLM-isolation
    # surface, so an accidental extra key here would be a real SR-008 regression.
    assert set(result.keys()) == {"manifests", "dependencies"}
