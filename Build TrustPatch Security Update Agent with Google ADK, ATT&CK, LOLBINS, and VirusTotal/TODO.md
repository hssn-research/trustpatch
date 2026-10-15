# TrustPatch TODO

## Phase 0 — Repository Foundation

- [x] Create Python package using `pyproject.toml`.
- [x] Add CLI framework.
- [x] Add typed configuration.
- [ ] Add structured logging.
- [x] Add JSON schemas.
- [x] Add test framework.
- [x] Add CI pipeline.
- [x] Add pre-commit/static quality checks. (`.pre-commit-config.yaml`: ruff + ruff-format + mypy)

## Phase 1 — Project Discovery

- [x] Implement Git detection.
- [x] Implement project root discovery.
- [x] Detect Python.
- [x] Detect Node.js.
- [x] Detect Go.
- [x] Detect Rust.
- [ ] Detect Java.
- [ ] Detect .NET.
- [x] Detect package manifests.
- [x] Detect lockfiles.
- [ ] Detect test commands. (checks are user-configured, not auto-discovered)
- [ ] Detect build commands. (checks are user-configured, not auto-discovered)

## Phase 2 — Dependency Inventory

- [x] Python inventory adapter.
- [x] Node inventory adapter.
- [x] Go inventory adapter.
- [x] Rust inventory adapter.
- [x] Normalize dependency records.
- [ ] Build dependency graph. (flat list only; no transitive graph)
- [ ] Identify direct/transitive dependencies. (go.mod indirect flag only; python/node lockfiles not walked)
- [x] Identify runtime/development scope.
- [x] Record lockfile provenance.

## Phase 3 — Security Intelligence

- [x] Integrate OSV.
- [x] Normalize advisory records.
- [x] Match affected ranges.
- [x] Identify fixed versions.
- [x] Record advisory evidence.
- [ ] Add vulnerability cache. (this item is about OSV specifically, used by the update planner — see the dedicated section below for the separate ATT&CK/LOLBAS/VirusTotal adapters, which do have caching now)
- [x] Add retry/backoff. (`OsvSource.query` now goes through the same bounded-retry-with-backoff helper (`integrations/sources._request_with_retry`) as the ATT&CK/LOLBAS/VirusTotal adapters — 3 attempts, exponential backoff, honors a numeric `Retry-After`. Unit-tested with a mocked flaky 503-then-200 response and a mocked always-503 response that still fails closed (`SourceError`, not an empty/"clean" result) after retries are exhausted — `tests/test_osv.py`.)
- [ ] Add offline evidence mode. (OSV specifically; a failed OSV lookup is already recorded as `unassessed` rather than treated as clean, but there is no cache-based offline fallback the way ATT&CK/LOLBAS/VirusTotal now have)

## Phase 3b — Defensive Intelligence Adapters (ATT&CK / LOLBAS / VirusTotal)

Separate from Phase 3's OSV-driven vulnerability intelligence: these three feed
the read-only, non-authoritative `trustpatch intel` command (docs/DEFENSIVE_SECURITY.md).
All items below were previously-documented production requirements that had
never been implemented; all are now live-verified (`tests/test_sources.py`, 30
tests, including real calls against the live ATT&CK and LOLBAS feeds) and
demonstrated through the actual CLI: a cold fetch (~4.2s, downloading the real
~53MB pinned ATT&CK release) followed by a cached call (~0.26s).

- [x] MITRE ATT&CK: pinned release instead of the moving `master` branch.
- [x] MITRE ATT&CK: bounded retries with backoff.
- [x] MITRE ATT&CK: local cache with recorded release + retrieval timestamp; stale-cache offline fallback.
- [x] LOLBAS: strict top-level feed-shape validation (a malformed feed now raises clearly instead of silently behaving like zero entries).
- [x] LOLBAS: last-known-good cache with atomic (write-temp-then-rename) replacement; stale-data indicator when the live feed is unreachable.
- [x] VirusTotal: bounded retries for transient errors; 429 handling that honors `Retry-After` and falls back to a stale cache when retries are exhausted.
- [x] VirusTotal: per-indicator caching with stale-result fallback.
- [x] VirusTotal: consistent audit fields (`indicator`, `timestamp`, `source`, `api_outcome`) on every result path, not just some of them.
- [x] Policy-gated sources. (fixed a real bug: `policies/*.yaml`'s `sources.mitre_attack`/`lolbas`/`virustotal` fields were pydantic-validated but never read anywhere — `Policy` didn't even expose them, and `intel` had no `--policy` option at all. A site setting `sources.virustotal: false` to comply with "do not submit confidential indicators to a public service" had that silently ignored. Now enforced: disabled sources are never queried over the network — live-verified with a test that fails if the network is touched while disabled.)
- [x] Audit completeness: `plan` and `intel` now record which `policy_path` governed the run, not just `apply`.
- [x] Architectural boundary locked in by a structural test: none of `policy.py`/`planner.py`/`verifier.py`/`executor.py` may reference the three intel-source classes (`test_decision_modules_never_import_the_intel_sources`).

## Phase 4 — SBOM

- [x] Generate CycloneDX SBOM.
- [ ] Store pre-update SBOM as a standalone artifact. (computed in-memory during verification; `scan` persists a general snapshot)
- [ ] Store post-update SBOM as a standalone artifact.
- [x] Compare SBOMs.
- [x] Verify expected dependency delta.

## Phase 5 — Risk Engine

- [x] Implement severity model.
- [x] Implement update magnitude detection.
- [ ] Detect runtime dependencies as a distinct risk factor.
- [x] Detect authentication dependencies.
- [x] Detect cryptographic dependencies.
- [x] Detect database dependencies.
- [ ] Detect native dependencies.
- [ ] Calculate blast radius.
- [x] Produce explainable risk reasons.

## Phase 6 — Policy Engine

- [x] YAML policy parser.
- [x] Default fail-closed policy.
- [x] Approval requirements.
- [x] Auto-apply allowlist (risk-tier threshold). (fixed a real bug: `auto_apply_maximum` was parsed but never actually enforced — `evaluate()` hardcoded a "low" threshold regardless of config; now genuinely compared, unit-tested at all three tiers)
- [ ] Deny rules (hard block on specific packages/ecosystems).
- [x] Policy validation. (pydantic-validated `policies/*.yaml`, unknown keys rejected, `auto_apply_maximum` restricted to a literal enum — `trustpatch schema --target policy`)
- [x] Policy integrity protection against `apply` trusting stale/tampered decisions. (fixed a real bug: `apply` read `approval_required` directly from the stored proposal JSON instead of re-deriving it — a hand-edited field could have skipped the approval gate; now re-evaluated fresh against current policy every time, live-proven via a real tamper attempt through the CLI).
- [x] Runtime detection of the *policy file itself* changing between propose and apply (SR-007). `Policy` now computes a `fingerprint` (a canonical digest of the parsed policy content) at load time; `propose` pins it into the proposal, and `apply` refuses — fail-closed, with a clear error naming the mismatch — if the policy file at the same `--policy` path has changed since. Live-proven end to end through the actual CLI (`tests/test_security_hardening.py::test_apply_refuses_when_the_policy_file_was_loosened_after_propose`): a candidate proposed under a strict policy (approval required) is loosened to auto-apply-eligible before `apply`, and `apply` still refuses; a legitimate re-`propose`+`run` under the new policy then applies normally, confirming the check blocks a stale/tampered binding specifically, not all policy changes forever.

## Phase 7 — Update Planner

- [x] Generate candidate updates.
- [x] Determine minimal fixed version.
- [x] Detect major/minor/patch changes.
- [x] Generate expected-change manifest.
- [x] Generate update plan.
- [ ] Support an explicit `--dry-run` flag on `run`/`apply` (scan/plan/propose are already non-mutating by construction).

## Phase 8 — Sandbox

- [x] Git worktree isolation. (live-verified: real worktree created under `/tmp`, torn down after use)
- [ ] Container execution. (bwrap provides network-namespace isolation for configured checks, not full container execution of the worktree preparation step itself)
- [x] Network isolation for configured checks. (live-verified: a real check inside a real sandbox tried to reach pypi.org and was genuinely blocked, via `bwrap --unshare-net`; gracefully — and honestly, via `CheckResult.network_isolated` — degrades to unisolated when `bwrap` isn't installed)
- [x] Resource limits for configured checks. (live-verified: CPU and memory rlimits genuinely killed a busy-loop and an over-allocation; process-count limiting is intentionally skipped when network isolation is active — see `checks.py`'s `_apply_resource_limits` docstring for the kernel-level reason)
- [x] Timeouts.
- [ ] Temporary credentials.
- [ ] Artifact collection (check stdout/stderr captured in the report, not persisted as separate files).
- [x] Workspace cleanup. (live-verified)

## Phase 9 — Testing

- [x] Unit-test execution. (via configured `checks.test`)
- [ ] Integration-test execution as a distinct category.
- [x] Build execution. (via configured `checks.build`)
- [ ] Package resolution validation beyond resolved-version matching.
- [x] SAST integration. (via configured `checks.sast`, tool-agnostic)
- [x] Secret scanning. (via configured `checks.secrets`, tool-agnostic)
- [x] Dependency vulnerability rescan.

## Phase 10 — Independent Verification

- [x] Separate verifier implementation. (does not import the executor)
- [x] Verify resolved versions.
- [x] Verify lockfiles. (presence-of-refresh check, not lockfile-content correctness)
- [x] Verify expected files.
- [x] Detect unexpected files.
- [ ] Compare full dependency graphs. (single-dependency + whole-SBOM diff only, not transitive graph comparison)
- [x] Rebuild, when a build check is configured. (live-verified: real configured test/sast commands ran inside a real `run`'s verification pass)
- [x] Rerun required tests, when a test check is configured. (live-verified)
- [x] Verify vulnerability removal.
- [x] Verify SBOM delta. (fixed a real gap: only version *changes* to existing components were checked, not entirely new/vanished ones — an executor bug slipping in an unrelated dependency would have gone undetected since the manifest file itself is expected to change too; now checked, unit-tested)

## Phase 11 — Approval

- [x] Approval objects.
- [x] CLI approval flow.
- [x] Approval expiration.
- [x] Evidence digest binding.
- [x] Approval identity.
- [x] Rejection reason.
- [x] Audit approval events.

## Phase 12 — Application

- [x] Apply approved patch.
- [x] Verify target commit.
- [x] Final dependency scan.
- [x] Final security scan (vulnerability rescan always runs for security-fix candidates).
- [x] Final test, when a test check is configured. (live-verified)
- [x] Rollback command.

## Phase 13 — Audit

- [x] Structured audit events.
- [x] Event IDs.
- [x] Evidence hashes.
- [x] Append-only storage.
- [ ] Optional cryptographic signatures. (hash-chain tamper *evidence* implemented; no signing key support yet)
- [ ] Human-readable reports. (JSON only)
- [x] JSON export.

## Phase 14 — Integrations

- [ ] GitHub pull requests.
- [ ] GitLab merge requests.
- [ ] CI integration.
- [ ] Scheduled scanning.
- [ ] Slack/email notifications.
- [ ] Web dashboard.

## Phase 15 — Hardening

`tests/test_security_hardening.py` (16 tests) plus targeted additions elsewhere now
cover most of this phase with real, executed evidence — not just design review.
Independently re-verified 2026-10-12 (fresh pytest/ruff/mypy/pip-audit run, two full
live lifecycles, a live audit-tamper simulation, live bwrap network isolation, and
live CPU/memory rlimit enforcement) — see docs/TODOFINISH.md's Evidence section.

- [ ] Threat model review. (no formal document/sign-off; the invariants in docs/DESIGN.md §2 and docs/AGENT-INSTRUCTION.md's Absolute Rules serve as an informal one)
- [x] Sandbox escape testing. (live-verified against a real bwrap sandbox: a malicious check cannot write outside its worktree to a genuinely read-only host path; confirmed it *can* still write inside its worktree, so isolation isn't over-aggressive)
- [x] Dependency confusion testing. (a lookalike package name is proven to be queried against OSV using its own exact, unmodified name — never fuzzy-matched against a trusted name)
- [x] Malicious package fixtures. (a `package.json` with a malicious `postinstall` script is proven to never execute — the test fails loudly if the executor ever calls `subprocess` at all)
- [x] Prompt injection fixtures. (shell metacharacters, script tags, template-injection payloads, and null bytes in attacker-controlled OSV advisory text are proven to never influence the chosen fix version and to round-trip safely through JSON output)
- [x] Policy bypass tests. (a forged approval digest for a different proposal/verification pair is rejected; a real tamper of the stored `approval_required` proposal field is rejected end to end through the actual CLI — see docs/TODOFINISH.md bug #6)
- [x] Audit tamper tests. (deletion and reordering of real audit events are now covered, not just a single-field edit; live-verified against the real audit log from an actual end-to-end run, not just a synthetic one)
- [x] Reproducibility tests. (planner output — candidate selection and policy evaluation — proven deterministic for identical inputs)
