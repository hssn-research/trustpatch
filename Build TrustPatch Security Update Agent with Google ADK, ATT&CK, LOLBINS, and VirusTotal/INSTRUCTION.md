# TrustPatch Operational Instructions

## Purpose

These instructions define how operators use TrustPatch safely.

## Modes

### Observe

```bash
trustpatch scan ./project
```

No changes.

### Plan

```bash
trustpatch plan ./project
```

Creates candidate updates without modifying the target.

### Propose

```bash
trustpatch propose ./project --update-id UPDATE-ID
```

Commits to one plan candidate as a formal, digest-bound proposal. Required
before `run`. A low-confidence/unresolved candidate (no fixed version could be
determined automatically) requires an explicit human override here:
`--override-version`, `--override-actor`, `--override-reason`.

### Prepare

```bash
trustpatch run ./project --update-id UPDATE-ID
```

Creates an isolated git worktree, applies the proposed candidate there, and
independently verifies it. `--mode prepare-only` is the only supported mode and
is the default — it never touches the primary working tree. Requires the
target to be a git repository.

### Verify

```bash
trustpatch verify ./project --update-id UPDATE-ID
```

Prints the independent verification report produced by the most recent `run`.

### Approve

```bash
trustpatch approve UPDATE-ID ./project --actor <name> --reason "<why>" [--expires-in-hours N]
```

Approvals must be explicit and auditable, and are bound to the exact proposal +
verification evidence reviewed — any later change to either invalidates the
approval.

### Reject

```bash
trustpatch reject UPDATE-ID ./project --actor <name> --reason "<why>"
```

Rejected changes must not be applied.

### Apply

```bash
trustpatch apply ./project --update-id UPDATE-ID
```

Applies the candidate to the primary working tree only if verification passed
and (for high-risk changes) a matching approval exists. Refuses if the primary
tree has moved since verification, and automatically rolls back if final
post-apply verification fails.

### Rollback

```bash
trustpatch rollback ./project --update-id UPDATE-ID
```

Reverts an applied change via `git revert`, preserving history. Requires the
rollback record `apply` created.

## Recommended Operator Workflow

1. Start with `scan`.
2. Review dependency and vulnerability evidence.
3. Run `plan`.
4. `propose` the exact candidate to move forward.
5. `run` to prepare it in a sandbox and get an independent verification report.
6. Review tests, verification, and any advisories.
7. `approve` only the exact candidate represented by the evidence (or `reject`).
8. `apply`.
9. Review the final verification `apply` produced.
10. Retain the audit report (`trustpatch audit ./project`, or `--check` to
    verify its tamper-evident hash chain).

## Approval Checklist

Before approval verify:

- Correct project.
- Correct dependency.
- Current version.
- Proposed version.
- Advisory evidence.
- Expected files.
- Actual diff.
- Tests passed.
- Build passed where applicable.
- Vulnerability rescan completed.
- Independent verification passed.
- No unexpected changes.
- Rollback information exists.

## Emergency Security Updates

Emergency workflows should not bypass the audit trail.

If organizational policy allows emergency changes, use an explicit emergency policy that still records:

- who authorized it
- why it was urgent
- what changed
- evidence available at the time
- what post-change verification was performed

## Credentials

Never provide production credentials to TrustPatch.

Use short-lived, least-privilege credentials only where required by an approved integration.

## Network

Default sandbox network access is disabled.

If a package manager requires network access, use an allowlist and record:

- destination
- reason
- duration
- policy that authorized it

## Artifacts

Preserve:

- scan report
- update plan
- patch
- test output
- SBOM
- vulnerability report
- verification report
- approval record
- final audit record

## Defensive Intelligence Cache

`trustpatch intel` caches ATT&CK, LOLBAS, and (per-indicator) VirusTotal results
under `.trustpatch/cache/`. This is evidence infrastructure, not secret
material — it holds only already-public threat-intelligence data (ATT&CK
techniques, LOLBAS entries) or VirusTotal report metadata for hashes this
operator explicitly queried, keyed by the queried SHA-256. It is safe to
delete at any time (the next `intel` call simply re-fetches); TrustPatch does
not currently prune it automatically, so operators with a long-running
`.trustpatch/` directory and many distinct VirusTotal lookups should include
it in their own retention/cleanup process. It is covered by the project's
`.gitignore` (`.trustpatch/`) along with the rest of the control directory.

## Incident Handling

If TrustPatch behaves unexpectedly:

1. Stop the operation.
2. Preserve logs.
3. Destroy only temporary execution environments after evidence capture.
4. Do not apply pending changes.
5. Review unexpected file/network/process activity.
6. Escalate according to the organization's incident process.
