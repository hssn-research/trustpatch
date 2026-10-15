# TrustPatch Design Specification

## 1. Architecture

```text
Project
  │
  ▼
Project Detector
  │
  ▼
Dependency Inventory ───────► SBOM
  │                            │
  ▼                            ▼
Vulnerability Intelligence   Security Evidence
  │
  ▼
Risk Engine
  │
  ▼
Policy Engine
  │
  ▼
Update Planner
  │
  ▼
Disposable Worktree / Sandbox
  │
  ▼
Update Executor
  │
  ├── Unit Tests
  ├── Integration Tests
  ├── Build
  ├── SAST
  ├── Secret Scan
  ├── SBOM Regeneration
  └── Vulnerability Rescan
  │
  ▼
Independent Verifier
  │
  ├── Expected vs actual diff
  ├── Dependency resolution check
  ├── Rebuild
  ├── Test rerun
  ├── Security rescan
  └── Artifact comparison
  │
  ▼
Approval Gate
  │
  ├── Reject
  ├── Pending
  └── Approve
  │
  ▼
Target Apply
  │
  ▼
Final Verification
  │
  ▼
Audit Evidence
```

## 2. Trust Boundaries

### Boundary A — User Project

The source project is untrusted input. The agent must not assume that project scripts are safe.

### Boundary B — Dependency Execution

Package installation and build systems can execute arbitrary project/package lifecycle code. These operations must occur in an isolated environment.

### Boundary C — Agent Control Plane

The policy engine and approval mechanism determine mutation authority. LLM output must not cross this boundary by itself.

### Boundary D — Target Mutation

Applying a prepared change to the user's primary project is a privileged operation.

## 3. Components

### Orchestrator

Coordinates the workflow and state transitions.

### Project Detector

Identifies languages, package managers, lockfiles, manifests, build systems and test commands.

### Inventory Engine

Produces normalized dependency records:

```json
{
  "name": "requests",
  "version": "2.31.0",
  "ecosystem": "python",
  "direct": true,
  "scope": "runtime",
  "source": "uv.lock"
}
```

### Vulnerability Engine

Normalizes advisories from trusted vulnerability sources such as OSV and project-specific security feeds.

### Risk Engine

Calculates a policy-oriented risk classification using:

- Vulnerability severity.
- Exploitability.
- Runtime exposure.
- Dependency scope.
- Update magnitude.
- Compatibility risk.
- Blast radius.
- Project criticality.
- Verification confidence.

Risk must be explainable and deterministic.

### Update Planner

Maps a vulnerable/outdated dependency to one or more supported fixed versions.

The planner must distinguish:

- Direct vs transitive dependency.
- Security fix vs ordinary maintenance.
- Patch/minor/major update.
- Single-package vs coordinated update.
- Lockfile-only vs source-impacting change.

### Sandbox

Creates an isolated execution environment with:

- Temporary filesystem.
- Restricted network.
- CPU/memory/process limits.
- No production credentials.
- No host SSH credentials.
- No cloud credentials.
- No Docker socket.
- Timeouts.

### Update Executor

Performs only the approved candidate update inside the sandbox/worktree.

### Verification Engine

Independent from the updater. It verifies:

- Intended version resolution.
- Lockfile integrity.
- Git diff.
- Unexpected file changes.
- Build result.
- Tests.
- Security scan.
- Vulnerability status.
- SBOM delta.

### Policy Engine

Converts facts into authorization requirements.

Example:

```yaml
approval:
  required_for:
    - major_version
    - cryptography
    - authentication
    - database
    - native_library
    - runtime_security_dependency
```

### Approval Service

Stores explicit human approval/rejection and identity, timestamp, change identifier and evidence digest.

### Audit Engine

Produces structured, append-only events.

## 4. State Machine

```text
DISCOVERED
   ↓
INVENTORIED
   ↓
ASSESSED
   ↓
PLANNED
   ↓
SANDBOX_CREATED
   ↓
UPDATED
   ↓
TESTED
   ↓
VERIFIED
   ├── failed → REJECTED
   └── passed
          ↓
       POLICY_CHECK
       ├── denied → REJECTED
       ├── approval → PENDING_APPROVAL
       └── automatic → APPROVED
                       ↓
                     APPLIED
                       ↓
                  FINAL_VERIFIED
                       ↓
                    COMPLETE
```

## 5. Expected-Change Model

Every update candidate creates an expected-change manifest.

```json
{
  "dependency": "requests",
  "from": "2.31.0",
  "to": "2.32.4",
  "expected_files": [
    "pyproject.toml",
    "uv.lock"
  ]
}
```

Any unexpected source/security/configuration modification should block automatic application.

## 6. Independent Verification

The verifier should be a separate logical component and preferably execute a separate code path from the update planner.

It should independently reconstruct the resolved dependency state rather than trusting the updater's result.

## 7. LLM Role

Permitted:

- Explain advisories.
- Summarize release notes.
- Explain test failures.
- Produce human-readable reports.
- Suggest candidate updates.

Not authoritative for:

- Vulnerability existence.
- Version resolution.
- Approval.
- Policy decisions.
- Credential access.
- Production execution.
- Final verification.

## 8. Audit Design

Every sensitive action produces an event:

```json
{
  "event_id": "evt_...",
  "timestamp": "2026-09-24T10:00:00Z",
  "agent_version": "0.1.0",
  "project": "example",
  "operation": "dependency_update",
  "dependency": "requests",
  "before": "2.31.0",
  "after": "2.32.4",
  "policy_decision": "approval_required",
  "verification": "passed"
}
```

Production deployments should use canonical serialization and cryptographic signatures for audit records.

## 9. Failure Policy

Default behavior is fail-closed.

If:

- tests fail,
- build fails,
- verification is incomplete,
- vulnerability remains,
- unexpected changes appear,
- policy cannot be evaluated,
- sandbox isolation fails,
- evidence is inconsistent,

then the candidate is not applied.

## 10. Rollback

The system must retain:

- Original commit.
- Candidate commit.
- Patch.
- Lockfile state.
- Verification evidence.
- Approval evidence.

Rollback must be deterministic and must itself be audited.
