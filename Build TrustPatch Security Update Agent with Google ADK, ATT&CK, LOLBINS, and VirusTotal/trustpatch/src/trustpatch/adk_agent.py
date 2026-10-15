"""Optional Google ADK surface; deterministic tools remain authoritative."""

from .discovery import detect_manifests, inventory


def build_agent():
    try:
        from google.adk.agents import Agent
    except ImportError as exc:
        raise RuntimeError("Install the optional ADK extra: pip install 'trustpatch[adk]'") from exc

    def inspect_project(path: str) -> dict:
        from pathlib import Path

        root = Path(path).resolve()
        manifests = detect_manifests(root)
        return {
            "manifests": [m.__dict__ for m in manifests],
            "dependencies": [d.__dict__ for d in inventory(root, manifests)],
        }

    return Agent(
        name="trustpatch_defensive_security",
        model="gemini-2.5-flash",
        instruction=(
            "Explain evidence and summarize findings. Never authorize changes, suppress findings, or claim scans "
            "passed. Use inspect_project only for deterministic project facts."
        ),
        tools=[inspect_project],
    )
