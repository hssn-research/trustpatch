# TrustPatch Requirements

## 1. Functional Requirements

### FR-001 Project Detection

The system shall detect supported project ecosystems automatically.

### FR-002 Dependency Inventory

The system shall enumerate direct and transitive dependencies where ecosystem tooling permits.

### FR-003 Lockfile Awareness

The system shall recognize and preserve package-manager lockfiles.

### FR-004 Vulnerability Detection

The system shall identify dependencies affected by known vulnerabilities using trusted vulnerability intelligence.

### FR-005 Outdated Dependency Detection

The system shall identify dependencies with available newer versions.

### FR-006 Update Planning

The system shall create an evidence-backed update plan.

### FR-007 Risk Classification

The system shall classify updates according to configurable policy.

### FR-008 Sandbox Execution

Candidate changes shall be prepared in an isolated execution environment.

### FR-009 Testing

The system shall run configured tests and record results.

### FR-010 Security Verification

The system shall run configured security checks and dependency rescans.

### FR-011 Independent Verification

The system shall verify the result independently of the update operation.

### FR-012 Human Approval

The system shall require explicit human approval for policy-defined high-risk changes.

### FR-013 Exact Approval Binding

Approval shall be bound to the exact candidate change and evidence digest.

### FR-014 Final Verification

The system shall verify the target after an approved change is applied.

### FR-015 Audit

Security-sensitive operations shall produce structured audit events.

### FR-016 Rollback

The system shall preserve enough state to support deterministic rollback.

## 2. Security Requirements

### SR-001 Least Privilege

The agent shall operate with minimum required permissions.

### SR-002 Credential Isolation

Production credentials shall not be exposed to sandboxed project code.

### SR-003 Network Isolation

Sandbox network access shall be disabled by default.

### SR-004 Resource Limits

Sandbox executions shall have CPU, memory, process and time limits.

### SR-005 Fail Closed

Ambiguous or failed security verification shall prevent automatic application.

### SR-006 Unexpected Changes

Unexpected files or security-sensitive modifications shall block automatic application.

### SR-007 Policy Integrity

Agent execution shall not be able to silently modify its own authorization policy.

### SR-008 LLM Isolation

LLM output shall not directly grant security-sensitive authority.

### SR-009 Audit Integrity

Production audit records should be tamper-evident.

### SR-010 Reproducibility

Candidate updates should be reproducible from recorded inputs whenever practical.

## 3. Quality Requirements

- Python 3.12+.
- Typed Python APIs.
- Automated unit and integration tests.
- Deterministic policy evaluation.
- Structured logging.
- JSON schemas for machine-readable evidence.
- Clear CLI errors.
- Documentation for supported ecosystems.
- No silent mutation.

## 4. MVP Acceptance Criteria

The MVP must:

- scan Python and Node.js projects;
- identify dependencies;
- identify known vulnerabilities;
- propose fixed versions;
- create an isolated worktree;
- apply candidate updates there;
- execute tests;
- generate a before/after SBOM;
- rescan vulnerabilities;
- independently verify the candidate;
- require approval for configured high-risk changes;
- apply only approved changes;
- produce an audit report.
