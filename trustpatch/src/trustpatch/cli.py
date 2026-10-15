from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn

import typer

from . import approval as approval_module
from . import sandbox as sandbox_module
from . import sbom as sbom_module
from .audit import append_event, digest, verify_chain
from .config import json_schema, load_config, policy_json_schema
from .constants import CONTROL_DIR_NAME
from .discovery import detect_manifests, git_root, inventory
from .executor import ExecutorError, apply_manifest_update
from .integrations.sources import LolbasSource, MitreAttackSource, SourceError, VirusTotalSource
from .models import Candidate
from .planner import plan_project
from .policy import Policy
from .sandbox import Sandbox, SandboxError
from .verifier import verify as run_verification
from .versions import classify_bump

app = typer.Typer(
    help="Fail-closed defensive security maintenance agent.",
    context_settings={"help_option_names": ["-h", "--help"]},
)

DEFAULT_POLICY_PATH = Path("policies/default.yaml")


def root_for(path: Path) -> Path:
    return git_root(path.resolve()) or path.resolve()


def control_dir(root: Path) -> Path:
    return root / CONTROL_DIR_NAME


def fail(message: str) -> NoReturn:
    typer.secho(f"error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=1)


def load_checks_config(config: Path | None) -> dict[str, list[list[str]]]:
    return load_config(config).checks.as_dict()


def _load_json(path: Path) -> dict[str, Any] | None:
    return json.loads(path.read_text()) if path.exists() else None


def _binding_digest(proposal: dict[str, Any], verification: dict[str, Any]) -> str:
    return digest({"proposal": proposal, "verification": verification})


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
    bom = sbom_module.generate(root.name, deps)
    sbom_path = control_dir(root) / "sbom.json"
    sbom_path.parent.mkdir(parents=True, exist_ok=True)
    sbom_path.write_text(json.dumps(bom, indent=2))
    print(json.dumps(result, indent=2))
    append_event(control_dir(root), "scan", result)


@app.command()
def plan(
    path: Path = typer.Argument(..., exists=True, file_okay=False),
    policy: Path = typer.Option(DEFAULT_POLICY_PATH),
):
    """Assess dependencies against trusted vulnerability intelligence (OSV) and
    produce a conservative update plan. Read-only with respect to the project."""
    root = root_for(path)
    manifests = detect_manifests(root)
    deps = inventory(root, manifests)
    rules = Policy(policy)
    result = plan_project(deps, manifests, rules)
    result = {"project_root": str(root), "mode": "prepare-only", "policy_path": str(policy), **result}
    artifact = control_dir(root) / "plan.json"
    artifact.parent.mkdir(exist_ok=True)
    artifact.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    append_event(control_dir(root), "plan", result)


@app.command()
def propose(
    path: Path = typer.Argument(..., exists=True, file_okay=False),
    update_id: str = typer.Option(..., "--update-id"),
    policy: Path = typer.Option(DEFAULT_POLICY_PATH),
    override_version: str | None = typer.Option(
        None, "--override-version", help="Manually pin a target version for a low-confidence candidate."
    ),
    override_actor: str | None = typer.Option(None, "--override-actor"),
    override_reason: str | None = typer.Option(None, "--override-reason"),
):
    """Commit to one plan candidate as a formal, digest-bound proposal. This is
    the artifact that later approvals and applies are bound to. TrustPatch never
    auto-selects a version for a low-confidence/unresolved candidate — a human
    must supply --override-version, --override-actor and --override-reason."""
    root = root_for(path)
    plan_data = _load_json(control_dir(root) / "plan.json")
    if plan_data is None:
        fail("no plan found; run `trustpatch plan` first")
    candidate_dict = next((c for c in plan_data["candidates"] if c["update_id"] == update_id), None)
    if candidate_dict is None:
        fail(f"update_id {update_id!r} not found in the current plan")

    rules = Policy(policy)
    if candidate_dict["confidence"] != "confirmed":
        if not (override_version and override_actor and override_reason):
            fail(
                f"candidate {update_id!r} has confidence={candidate_dict['confidence']!r}; "
                "supply --override-version, --override-actor and --override-reason to propose it anyway"
            )
        override = {"actor": override_actor, "reason": override_reason, "at": datetime.now(UTC).isoformat()}
        candidate = Candidate.from_dict(candidate_dict)
        candidate.proposed_version = override_version
        candidate.confidence = "human_override"
        candidate.update_kind = classify_bump(candidate.dependency.version, override_version)
        candidate_dict = rules.evaluate(candidate).to_dict()
        candidate_dict["override"] = override

    proposal = {
        "update_id": update_id,
        "candidate": candidate_dict,
        "policy_path": str(policy),
        # SR-007: pins the exact policy content this proposal was risk/approval
        # classified under. `apply` refuses if the policy at this path has since
        # changed, so a loosened policy can never silently apply to a candidate
        # that was proposed/reviewed under a stricter one.
        "policy_fingerprint": rules.fingerprint,
        "created_at": datetime.now(UTC).isoformat(),
    }
    path_out = control_dir(root) / "proposals" / f"{update_id}.json"
    path_out.parent.mkdir(parents=True, exist_ok=True)
    path_out.write_text(json.dumps(proposal, indent=2))
    print(json.dumps(proposal, indent=2))
    append_event(control_dir(root), "propose", proposal)


@app.command()
def run(
    path: Path = typer.Argument(..., exists=True, file_okay=False),
    update_id: str = typer.Option(..., "--update-id"),
    mode: str = typer.Option("prepare-only", "--mode"),
    config: Path | None = typer.Option(None, "--config"),
    policy: Path = typer.Option(DEFAULT_POLICY_PATH),
):
    """Prepare a proposed candidate update inside a disposable git worktree and
    independently verify it. Never mutates the primary working tree."""
    if mode != "prepare-only":
        fail("only --mode prepare-only is supported; apply is a separate, explicit command")
    root = root_for(path)
    proposal = _load_json(control_dir(root) / "proposals" / f"{update_id}.json")
    if proposal is None:
        fail(f"no proposal for {update_id!r}; run `trustpatch propose` first")
    candidate_dict = proposal["candidate"]
    candidate = Candidate.from_dict(candidate_dict)

    try:
        sandbox = sandbox_module.create(root, update_id)
    except SandboxError as exc:
        fail(str(exc))

    try:
        apply_manifest_update(sandbox.worktree, candidate)
    except ExecutorError as exc:
        sandbox.cleanup()
        fail(str(exc))

    rules = Policy(policy)
    checks = load_checks_config(config)
    report = run_verification(
        sandbox, candidate, checks=checks, require_lockfile_refresh=rules.require_lockfile_refresh
    )
    report_dict = report.to_dict()
    report_dict["base_commit"] = sandbox.base_commit
    report_dict["sandbox_worktree"] = str(sandbox.worktree)

    verification_path = control_dir(root) / "verifications" / f"{update_id}.json"
    verification_path.parent.mkdir(parents=True, exist_ok=True)
    verification_path.write_text(json.dumps(report_dict, indent=2))
    print(json.dumps(report_dict, indent=2))
    append_event(control_dir(root), "prepare", report_dict)

    sandbox.cleanup()

    if not report.passed:
        typer.secho(
            "verification failed; candidate will not be eligible for approval/apply", fg=typer.colors.YELLOW, err=True
        )
        raise typer.Exit(code=2)


@app.command()
def verify(
    path: Path = typer.Argument(..., exists=True, file_okay=False),
    update_id: str = typer.Option(..., "--update-id"),
):
    """Print the last independent verification report for a candidate."""
    root = root_for(path)
    report = _load_json(control_dir(root) / "verifications" / f"{update_id}.json")
    if report is None:
        fail(f"no verification report for {update_id!r}; run `trustpatch run --update-id {update_id}` first")
    print(json.dumps(report, indent=2))


@app.command()
def approve(
    update_id: str,
    path: Path = typer.Argument(..., exists=True, file_okay=False),
    actor: str = typer.Option(..., help="Identity of the human approver."),
    reason: str = typer.Option(..., help="Why this exact change is authorized."),
    expires_in_hours: float | None = typer.Option(
        None, "--expires-in-hours", help="Approval becomes invalid for apply after this many hours."
    ),
):
    """Record explicit human approval, bound to the exact proposal + verification
    evidence reviewed. Approval is invalidated automatically if either changes,
    or once it expires."""
    root = root_for(path)
    proposal = _load_json(control_dir(root) / "proposals" / f"{update_id}.json")
    verification = _load_json(control_dir(root) / "verifications" / f"{update_id}.json")
    if proposal is None or verification is None:
        fail(f"missing proposal or verification for {update_id!r}")
    if not verification["passed"]:
        fail("cannot approve a candidate whose independent verification failed")
    evidence_digest = _binding_digest(proposal, verification)
    expires_at = (
        (datetime.now(UTC) + timedelta(hours=expires_in_hours)).isoformat() if expires_in_hours is not None else None
    )
    record = approval_module.record(
        control_dir(root), update_id, "approved", actor, reason, evidence_digest, expires_at
    )
    print(json.dumps(record.to_dict(), indent=2))
    append_event(control_dir(root), "approve", record.to_dict())


@app.command()
def reject(
    update_id: str,
    path: Path = typer.Argument(..., exists=True, file_okay=False),
    actor: str = typer.Option(...),
    reason: str = typer.Option(...),
):
    """Record explicit rejection. A rejected candidate cannot be applied."""
    root = root_for(path)
    proposal = _load_json(control_dir(root) / "proposals" / f"{update_id}.json")
    verification = _load_json(control_dir(root) / "verifications" / f"{update_id}.json") or {}
    if proposal is None:
        fail(f"no proposal for {update_id!r}")
    evidence_digest = _binding_digest(proposal, verification)
    record = approval_module.record(control_dir(root), update_id, "rejected", actor, reason, evidence_digest)
    print(json.dumps(record.to_dict(), indent=2))
    append_event(control_dir(root), "reject", record.to_dict())


@app.command()
def apply(
    path: Path = typer.Argument(..., exists=True, file_okay=False),
    update_id: str = typer.Option(..., "--update-id"),
    policy: Path = typer.Option(DEFAULT_POLICY_PATH),
):
    """Apply an authorized candidate to the primary working tree, then
    independently re-verify the result. Refuses on any ambiguous or missing
    evidence (fail-closed) and rolls back automatically if final verification
    fails after mutation."""
    root = root_for(path)
    proposal = _load_json(control_dir(root) / "proposals" / f"{update_id}.json")
    verification = _load_json(control_dir(root) / "verifications" / f"{update_id}.json")
    if proposal is None or verification is None:
        fail(f"missing proposal or verification for {update_id!r}; run propose and run first")
    if not verification["passed"]:
        fail("independent verification did not pass; refusing to apply")

    candidate_dict = proposal["candidate"]
    rules = Policy(policy)
    # SR-007: refuse if the policy at this path has changed since `propose` ran
    # against it — otherwise an edit to policies/*.yaml between review and apply
    # (loosening `required_for`, raising `auto_apply_maximum`) would silently
    # change the authorization decision for a candidate a human already reviewed
    # under the old, stricter policy.
    if proposal.get("policy_fingerprint") != rules.fingerprint:
        fail(
            "policy file has changed since this candidate was proposed (fingerprint mismatch); "
            "re-run `trustpatch propose` and `trustpatch run` under the current policy before applying"
        )
    candidate = Candidate.from_dict(candidate_dict)
    # Never trust the stored `approval_required` boolean for a security
    # decision — it's a plain field in a JSON file TrustPatch itself writes
    # into the project (.trustpatch/proposals/*.json), so a direct edit of
    # that one field (accidental or adversarial) must not be able to bypass
    # the approval gate. Re-derive it fresh from the candidate's structural
    # facts (dependency version, proposed version, advisories, confidence)
    # against the *current* policy instead.
    rules.evaluate(candidate)
    approval_required = candidate.approval_required
    evidence_digest = _binding_digest(proposal, verification)

    if approval_required:
        record = approval_module.load(control_dir(root), update_id)
        ok, why = approval_module.is_valid(record, evidence_digest)
        if not ok or record is None:
            fail(f"human approval required and not satisfied: {why}")
        authorization = {"mode": "human_approval", "approval": record.to_dict()}
    else:
        authorization = {"mode": "automatic", "policy": str(policy), "auto_apply_maximum": rules.auto_max}

    current_head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10, check=True
    ).stdout.strip()
    if current_head != verification.get("base_commit"):
        fail("primary tree HEAD has moved since verification; re-run `trustpatch run` and re-verify before applying")

    dep = candidate.dependency

    before_deps = inventory(root, detect_manifests(root))
    original_files = {f: (root / f).read_text() for f in candidate.expected_files if (root / f).exists()}

    try:
        apply_manifest_update(root, candidate)
    except ExecutorError as exc:
        fail(str(exc))

    subprocess.run(
        ["git", "-C", str(root), "add", *candidate.expected_files],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    commit_message = (
        f"trustpatch: update {dep.name} to {candidate.proposed_version} ({update_id})\n\n"
        f"evidence_digest: {evidence_digest}"
    )
    commit = subprocess.run(
        ["git", "-C", str(root), "commit", "-m", commit_message],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if commit.returncode != 0:
        for rel_path, content in original_files.items():
            (root / rel_path).write_text(content)
        fail(f"failed to commit the applied change; restored original files: {commit.stderr.strip()}")

    pseudo_sandbox = Sandbox(root=root, worktree=root, base_commit=current_head)
    final_report = run_verification(
        pseudo_sandbox,
        candidate,
        checks={},
        require_lockfile_refresh=rules.require_lockfile_refresh,
        before_deps=before_deps,
    )

    if not final_report.passed:
        subprocess.run(
            ["git", "-C", str(root), "revert", "--no-edit", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        for rel_path, content in original_files.items():
            (root / rel_path).write_text(content)
        failure = {"update_id": update_id, "reasons": final_report.reasons, "rolled_back": True}
        append_event(control_dir(root), "apply_failed_rolled_back", failure)
        fail(f"final verification failed after apply; rolled back automatically: {final_report.reasons}")

    new_head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10, check=True
    ).stdout.strip()
    rollback_record = {
        "update_id": update_id,
        "pre_apply_commit": current_head,
        "candidate_commit": new_head,
        "expected_files": candidate.expected_files,
    }
    rollback_path = control_dir(root) / "rollback" / f"{update_id}.json"
    rollback_path.parent.mkdir(parents=True, exist_ok=True)
    rollback_path.write_text(json.dumps(rollback_record, indent=2))

    result = {
        "update_id": update_id,
        "authorization": authorization,
        "pre_apply_commit": current_head,
        "candidate_commit": new_head,
        "final_verification": final_report.to_dict(),
    }
    print(json.dumps(result, indent=2))
    append_event(control_dir(root), "apply", result)


@app.command()
def rollback(
    path: Path = typer.Argument(..., exists=True, file_okay=False),
    update_id: str = typer.Option(..., "--update-id"),
):
    """Revert an applied change via `git revert`, preserving history. Requires a
    rollback record created by a prior `apply`."""
    root = root_for(path)
    record = _load_json(control_dir(root) / "rollback" / f"{update_id}.json")
    if record is None:
        fail(f"no rollback record for {update_id!r}")
    result = subprocess.run(
        ["git", "-C", str(root), "revert", "--no-edit", record["candidate_commit"]],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    outcome = {
        "update_id": update_id,
        "reverted_commit": record["candidate_commit"],
        "returncode": result.returncode,
        "stderr": result.stderr.strip(),
    }
    print(json.dumps(outcome, indent=2))
    append_event(control_dir(root), "rollback", outcome)
    if result.returncode != 0:
        raise typer.Exit(code=1)


@app.command()
def audit(
    path: Path = typer.Argument(..., exists=True, file_okay=False),
    check: bool = typer.Option(False, "--check", help="Verify the audit log's tamper-evident hash chain."),
):
    """Show, or independently verify the integrity of, the append-only audit log."""
    root = root_for(path)
    if check:
        result = verify_chain(control_dir(root))
        print(json.dumps(vars(result), indent=2))
        if not result.valid:
            raise typer.Exit(code=1)
        return
    log = control_dir(root) / "audit.jsonl"
    if log.exists():
        print(log.read_text(), end="")
    else:
        print("No audit events recorded.")


@app.command()
def intel(
    path: Path = typer.Argument(..., exists=True, file_okay=False),
    sha256: str | None = typer.Option(None, help="Optional SHA-256 for a VirusTotal report lookup."),
    policy: Path = typer.Option(DEFAULT_POLICY_PATH),
):
    """Collect read-only defensive context from ATT&CK, LOLBAS, and VirusTotal.

    Each source is individually gated by `sources.mitre_attack`/`lolbas`/
    `virustotal` in the policy file — set one to `false` to hard-disable that
    query path (e.g. for organizations that must never send indicators to a
    public service; see docs/DEFENSIVE_SECURITY.md's VirusTotal confidentiality
    note). Results are cached under `.trustpatch/cache/` with the retrieval
    timestamp (and, for ATT&CK, the pinned release) always recorded, and fall
    back to a last-known-good snapshot — explicitly marked stale — when a
    source is temporarily unreachable.
    """
    root = root_for(path)
    rules = Policy(policy)
    cache_dir = control_dir(root) / "cache"
    sources: dict[str, Any] = {}

    if rules.sources.mitre_attack:
        try:
            outcome = MitreAttackSource(cache_path=cache_dir / "mitre_attack.json").techniques()
            sources["mitre_attack"] = {
                "status": "ok",
                "technique_count": len(outcome.data),
                "retrieved_at": outcome.retrieved_at,
                "from_cache": outcome.from_cache,
                "stale": outcome.stale,
                **outcome.extra,
            }
        except SourceError as exc:
            sources["mitre_attack"] = {"status": "unavailable", "error": str(exc)}
    else:
        sources["mitre_attack"] = {"status": "disabled_by_policy"}

    if rules.sources.lolbas:
        try:
            outcome = LolbasSource(cache_path=cache_dir / "lolbas.json").binaries()
            sources["lolbas"] = {
                "status": "ok",
                "entry_count": len(outcome.data),
                "retrieved_at": outcome.retrieved_at,
                "from_cache": outcome.from_cache,
                "stale": outcome.stale,
                **outcome.extra,
            }
        except SourceError as exc:
            sources["lolbas"] = {"status": "unavailable", "error": str(exc)}
    else:
        sources["lolbas"] = {"status": "disabled_by_policy"}

    if sha256:
        if rules.sources.virustotal:
            try:
                sources["virustotal"] = VirusTotalSource(cache_dir=cache_dir / "virustotal").lookup_hash(sha256)
            except (SourceError, ValueError) as exc:
                sources["virustotal"] = {"status": "unavailable", "error": str(exc), "indicator": sha256}
        else:
            sources["virustotal"] = {"status": "disabled_by_policy", "indicator": sha256}
    else:
        sources["virustotal"] = {"status": "not_requested"}

    result: dict[str, Any] = {"mutation": "none", "policy_path": str(policy), "sources": sources}
    print(json.dumps(result, indent=2))
    append_event(control_dir(root), "defensive_intelligence", result)


@app.command()
def schema(
    target: str = typer.Option("config", help="Which file family to print a JSON Schema for: 'config' or 'policy'."),
):
    """Print the JSON Schema for config/*.yaml or policies/*.yaml files."""
    if target == "policy":
        print(json.dumps(policy_json_schema(), indent=2))
    elif target == "config":
        print(json.dumps(json_schema(), indent=2))
    else:
        fail("--target must be 'config' or 'policy'")


if __name__ == "__main__":
    app()
