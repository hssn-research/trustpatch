from __future__ import annotations

import json
from pathlib import Path

import typer

from .audit import append_event
from .discovery import detect_manifests, git_root, inventory
from .integrations.sources import LolbasSource, MitreAttackSource, SourceError, VirusTotalSource
from .models import Candidate
from .policy import Policy

app = typer.Typer(help="Fail-closed defensive security maintenance agent.")


def root_for(path: Path) -> Path:
    return git_root(path.resolve()) or path.resolve()


@app.command()
def scan(path: Path = typer.Argument(..., exists=True, file_okay=False)):
    """Observe project metadata and dependencies without changing files."""
    root = root_for(path)
    manifests = detect_manifests(root)
    deps = inventory(root, manifests)
    result = {
        "project_root": str(root),
        "manifests": [m.__dict__ for m in manifests],
        "dependencies": [d.__dict__ for d in deps],
        "mutation": "none",
    }
    print(json.dumps(result, indent=2))
    append_event(root / ".trustpatch", "scan", result)


@app.command()
def plan(
    path: Path = typer.Argument(..., exists=True, file_okay=False),
    policy: Path = typer.Option(Path("policies/default.yaml")),
):
    """Create a conservative update plan from local evidence."""
    root = root_for(path)
    manifests = detect_manifests(root)
    deps = inventory(root, manifests)
    rules = Policy(policy)
    candidates = []
    for dep in deps:
        if dep.version not in ("*", ""):
            candidate = Candidate("upd_" + dep.name.replace("/", "_"), dep, dep.version, expected_files=[dep.source])
            candidates.append(rules.evaluate(candidate).to_dict())
    result = {"project_root": str(root), "candidates": candidates, "mode": "prepare-only"}
    artifact = root / ".trustpatch" / "plan.json"
    artifact.parent.mkdir(exist_ok=True)
    artifact.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    append_event(root / ".trustpatch", "plan", result)


@app.command()
def audit(path: Path = typer.Argument(..., exists=True, file_okay=False)):
    """Show the append-only audit log."""
    log = root_for(path) / ".trustpatch" / "audit.jsonl"
    if log.exists():
        print(log.read_text(), end="")
    else:
        print("No audit events recorded.")


@app.command()
def intel(
    path: Path = typer.Argument(..., exists=True, file_okay=False),
    sha256: str | None = typer.Option(None, help="Optional SHA-256 for a VirusTotal report lookup."),
):
    """Collect read-only defensive context from ATT&CK, LOLBAS, and VirusTotal."""
    root = root_for(path)
    result: dict[str, object] = {"mutation": "none", "sources": {}}
    try:
        result["sources"]["mitre_attack"] = {"status": "ok", "technique_count": len(MitreAttackSource().techniques())}
    except SourceError as exc:
        result["sources"]["mitre_attack"] = {"status": "unavailable", "error": str(exc)}
    try:
        result["sources"]["lolbas"] = {"status": "ok", "entry_count": len(LolbasSource().binaries())}
    except SourceError as exc:
        result["sources"]["lolbas"] = {"status": "unavailable", "error": str(exc)}
    if sha256:
        try:
            result["sources"]["virustotal"] = VirusTotalSource().lookup_hash(sha256)
        except (SourceError, ValueError) as exc:
            result["sources"]["virustotal"] = {"status": "unavailable", "error": str(exc)}
    else:
        result["sources"]["virustotal"] = {"status": "not_requested"}
    print(json.dumps(result, indent=2))
    append_event(root / ".trustpatch", "defensive_intelligence", result)


if __name__ == "__main__":
    app()
