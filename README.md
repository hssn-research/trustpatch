# TrustPatch Security Update Agent

## Overview

TrustPatch is a security-focused software maintenance agent that analyzes a sandboxed software project, inventories dependencies, identifies outdated or vulnerable components, proposes safe updates, tests candidate changes, independently verifies the resulting state, and requires explicit human approval before applying changes classified as high risk.

The core operating principle is:

> Inspect → Inventory → Assess → Propose → Isolate → Update → Test → Independently Verify → Approve → Apply → Verify Again → Audit.

TrustPatch is designed to reduce software supply-chain risk without turning an LLM into an unrestricted autonomous deployment operator.

## Goals

- Discover project ecosystems and dependency manifests.
- Build a normalized dependency inventory.
- Detect known vulnerabilities and outdated dependencies.
- Generate evidence-backed update candidates.
- Evaluate update risk deterministically.
- Work only inside disposable Git worktrees/sandboxes.
- Run project tests, builds, SAST, secret scanning, SBOM generation and vulnerability rescans.
- Independently verify that intended changes occurred and unexpected changes did not.
- Require human approval for configurable high-risk changes.
- Produce tamper-evident audit evidence.
- Support future GitHub/GitLab/CI integrations without weakening the trust boundary.

## Non-goals

TrustPatch is not:

- An unrestricted autonomous coding agent.
- A production deployment system.
- A replacement for a human security reviewer.
- A mechanism for bypassing organizational change-control processes.
- A system that treats LLM output as authoritative security evidence.

## Default Safety Model

The default mode is `prepare-only`.

The agent may inspect, analyze, create an isolated workspace, prepare a patch and execute verification. It must not modify the user's primary working tree unless policy and approval explicitly authorize the operation.

High-risk categories should normally require approval:

- Major version changes.
- Authentication and authorization dependencies.
- Cryptographic libraries.
- Database drivers and migrations.
- Native/system libraries.
- Runtime security dependencies.
- Build toolchains.
- CI/CD security configuration.
- Infrastructure/deployment definitions.
- Changes with failed, incomplete or ambiguous verification.

## Supported Ecosystems

Initial MVP:

- Python
- Node.js
- Go
- Rust

Planned:

- Java
- .NET
- PHP
- Ruby
- Docker/OCI
- Terraform
- Helm
- Kubernetes
- CI/CD dependency ecosystems

## Suggested Repository Layout

```text
trustpatch/
├── README.md
├── DESIGN.md
├── AGENT-INSTRUCTION.md
├── INSTRUCTION.md
├── REQUIREMENT.md
├── TODO.md
├── TODOFINISH.md
├── pyproject.toml
├── config/
├── policies/
├── schemas/
├── src/trustpatch/
├── tests/
├── examples/
└── docs/
```

## Core Commands

```bash
trustpatch scan ./project
trustpatch audit ./project
trustpatch plan ./project
trustpatch propose ./project --update-id UPDATE-ID
trustpatch run ./project --update-id UPDATE-ID          # --mode prepare-only is the default and only supported mode
trustpatch verify ./project --update-id UPDATE-ID
trustpatch approve UPDATE-ID ./project --actor <name> --reason "<why>"
trustpatch reject UPDATE-ID ./project --actor <name> --reason "<why>"
trustpatch apply ./project --update-id UPDATE-ID
trustpatch rollback ./project --update-id UPDATE-ID
trustpatch schema --target config   # or --target policy
```

See the top-level `README.md` (outside `docs/`) for a runnable quick-start walkthrough of this lifecycle.

## Security Invariants

1. Never modify the primary working tree during analysis.
2. Treat dependency installation and build scripts as untrusted code.
3. Never expose production credentials to the sandbox.
4. Never allow the LLM to independently authorize a security-sensitive mutation.
5. Expected changes must be compared with actual changes.
6. Failed or ambiguous verification blocks application.
7. High-risk changes require human approval.
8. Every security-sensitive action creates an audit event.
9. Rollback must be possible before mutation of the target.
10. Final state must be rescanned after application.

## Initial Success Criteria

The MVP is successful when it can:

1. Detect a Python or Node.js project.
2. Inventory direct and transitive dependencies.
3. Identify known vulnerabilities.
4. Produce an evidence-backed update plan.
5. Create a disposable worktree.
6. Apply the candidate update only there.
7. Run configured tests/build/security checks.
8. Independently verify the dependency graph and diff.
9. Produce an approval request when required.
10. Apply only explicitly authorized changes.
11. Produce a final verification and audit report.
