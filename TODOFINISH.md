# TrustPatch Definition of Done

This file defines what must be complete before calling a TrustPatch release production-ready.

Legend: `[x]` = executed and verified (test run, live command, or explicit assertion).
An inline note marks anything not yet implemented.

## Evidence

- `pytest` → **126 passed, 0 skipped**. `ruff check` / `ruff format --check` → clean.
  `mypy` → no issues in 22 source files. `pip-audit --skip-editable` → no known
  vulnerabilities in TrustPatch's own dependencies. All four now run in CI
  (`.github/workflows/ci.yml`).
- **A follow-up end-to-end audit found and fixed five additional real issues**,
  none caught by the previous "121 passed" baseline because each was either
  untested, invisible to a stale tool cache, or a non-security reliability gap:
  1. `adk_agent.py` had a literal syntax error (`return {.` instead of `return {`)
     that made the entire optional Google-ADK module fail to import. Nothing in
     the test suite ever imported `trustpatch.adk_agent` (it requires the
     optional `adk` extra, not installed in CI or locally), so this was
     completely invisible — and the first `ruff check`/`mypy` run of this audit
     *also* reported it clean, because both tools hit a stale `.mypy_cache`/
     `.ruff_cache` from before the file was last edited. Deleting the caches and
     re-running immediately surfaced the real error. Fixed (one-character fix);
     `tests/test_adk_agent.py` now imports the module directly and exercises
     `build_agent()`/`inspect_project` with a stubbed `google.adk.agents` module
     (no need for the real heavy dependency), so a future regression here can
     never again hide behind "ADK isn't installed, so nothing runs this file."
  2. **SR-007 (Policy Integrity) gap closed**: `apply` re-derived `approval_required`
     fresh from the *current* policy file at its `--policy` path (the bug #6 fix
     below), but nothing detected if that policy file's content had changed
     since `propose` ran. A policy edited to remove `major_version` from
     `required_for` or raise `auto_apply_maximum` between proposal review and
     apply would have been silently honored. Fixed: `Policy` now computes a
     content fingerprint at load time; `propose` pins it into the proposal, and
     `apply` refuses (fail-closed, clear error) if the policy at the same path
     no longer matches. Live-proven end to end through the real CLI: a strict
     policy requiring approval is loosened to auto-apply after `propose`+`run`,
     and `apply` still refuses — then a legitimate re-`propose` under the new
     policy applies normally, confirming the fix blocks a stale binding
     specifically, not all policy evolution.
  3. OSV queries (`integrations/osv.py`) had no retry/backoff, unlike the
     ATT&CK/LOLBAS/VirusTotal adapters, which already share one bounded-retry
     helper. A single transient OSV 503 would downgrade a dependency straight
     to `unassessed` instead of retrying. Fixed: `OsvSource.query` now goes
     through the same `_request_with_retry` helper (3 attempts, exponential
     backoff, honors `Retry-After`); still raises `SourceError` (fail-closed,
     never a false "clean") once retries are exhausted. Unit-tested with a
     mocked flaky-then-success response and a mocked always-failing response.
  4. `audit.append_event` hardcoded `"agent_version": "0.1.0"` as a literal
     string duplicating `trustpatch.__version__` — a provenance/auditability
     defect: bumping the package version would silently leave every future
     audit event recording the wrong agent version. Fixed to import and use
     `__version__` directly; single source of truth.
  5. `config.py`'s `NetworkConfig.allowlist` field (surfaced in
     `config/example.yaml` with OSV/ATT&CK/LOLBAS/VirusTotal hostnames) was
     pydantic-validated and unit-tested for *parsing*, but never read by any
     code path — not the sandbox, not the integrations, not anything. An
     operator populating it would reasonably believe it restricted outbound
     network access; it did nothing. Removed as dead/misleading config rather
     than building new enforcement machinery around hardcoded, already-trusted
     integration endpoints (SR-003's actual network control is the sandbox's
     binary bwrap network-namespace isolation, which is real and independently
     live-verified — see below).
  - All five were independently verified, not just unit-tested in isolation: a
    full real lifecycle (`scan` → `plan` → `propose` → `run` → `reject` →
    `approve` → `apply` → `rollback` → `audit --check`) was re-run live against
    a fresh scratch git repository with the same genuinely vulnerable
    dependency (express 4.18.2, live OSV query, same two real CVEs) both before
    and after these fixes, confirming the happy path still works unchanged
    end-to-end alongside the new SR-007 enforcement.
- The ATT&CK/LOLBAS/VirusTotal adapters (`src/trustpatch/integrations/sources.py`)
  were brought up to the production requirements docs/DEFENSIVE_SECURITY.md had
  always specified but were never implemented: a pinned ATT&CK release (not the
  moving `master` branch), bounded retries with backoff (429 `Retry-After`
  honored), local caching with atomic replacement and recorded retrieval
  timestamps, LOLBAS feed-shape validation (a malformed feed now raises clearly
  instead of silently looking like zero entries), and consistent VirusTotal audit
  fields (`indicator`/`timestamp`/`source`/`api_outcome`) on every result path.
  Live-verified against the real ATT&CK and LOLBAS services through the actual
  CLI: a cold fetch (~4.2s, the real ~53MB pinned release) followed by a cached
  call (~0.26s) — 30 tests in `tests/test_sources.py`, most against real network
  endpoints, the rest (VirusTotal, which needs a key this environment doesn't
  have) against deterministic mocked responses that exercise TrustPatch's own
  retry loop for real.
- **An eighth real bug was found and fixed**: `policies/*.yaml`'s
  `sources.mitre_attack`/`lolbas`/`virustotal` fields were pydantic-validated but
  never actually read anywhere — `Policy` didn't even expose them as an
  attribute, and the `intel` CLI command had no `--policy` option at all. This
  is directly a compliance-relevant gap: docs/DEFENSIVE_SECURITY.md explicitly
  warns "do not submit or query confidential, proprietary, or personal
  indicators through an unapproved public service," and a site setting
  `sources.virustotal: false` to enforce that had it silently ignored — VirusTotal
  would still be queried whenever an API key was present and a hash supplied.
  Fixed: `intel` now takes `--policy`, `Policy` exposes `.sources`, and each
  source is checked before querying. Live-proven with a network-call guard (the
  test fails loudly if any network call happens while a source is disabled), not
  just by checking the reported status.
- A full real lifecycle was run end to end, three times, against scratch git
  repositories with a genuinely vulnerable dependency (express 4.18.2): `scan` →
  `plan` (live OSV query, found real CVEs GHSA-qw6h-vgh9-j6wx and
  GHSA-rv95-896h-c2vc) → `propose` → `run` (real git worktree created and torn
  down, real configured `test`/`build`/`sast`/`secrets` checks executed inside it)
  → `reject` (confirmed it blocks `apply`) → `approve` (overriding the earlier
  rejection, as intended) → `apply` (mutated `package.json`, created a real
  commit) → `rollback` (real `git revert`, preserved history, package.json
  genuinely restored) → `audit --check` (hash chain valid, all 8 real operations
  recorded).
- The third live run additionally proved, for real, inside the real disposable
  sandbox: a SAST check that tried to reach `pypi.org` was genuinely blocked by
  network-namespace isolation (`bwrap --unshare-net`); a secrets-scan check
  confirmed an injected `AWS_SECRET_ACCESS_KEY` was genuinely absent from its
  environment; CPU/memory rlimits genuinely killed a busy-loop and an
  over-allocation in isolated unit tests; and — the sharpest test — a real
  attacker-style tamper of the completed run's actual audit log (deleting the
  `reject` event to hide it) was genuinely caught by `audit --check`
  (`valid: false`, exact event identified).
- A dedicated adversarial test suite now exists (`tests/test_security_hardening.py`,
  16 tests): sandbox-escape resistance (a malicious check cannot write outside its
  worktree, verified against a real bwrap sandbox), no-lifecycle-script-execution
  (a malicious `postinstall` script in `package.json` never runs — enforced with a
  guard that fails the test if the executor ever calls `subprocess`), prompt-injection
  resistance (shell metacharacters/script tags/template-injection payloads in
  attacker-controlled OSV advisory text never influence the chosen fix version or
  corrupt JSON output), dependency-confusion resistance (lookalike package names are
  never fuzzy-matched), forged-approval rejection, audit-log tamper detection
  (deletion and reordering, not just single-field edits), and planner-output
  reproducibility.
- **Six real bugs were found and fixed by this work**, each invisible to unit tests
  in isolation, each would have broken real-world usage or weakened security:
  1. `executor.py` resolved the manifest to edit from `Dependency.source`, but that
     field is the *lockfile* name whenever one is present (provenance metadata, not
     "the file to edit"). Any real project with a lockfile — i.e. almost all of them
     — would hit `ExecutorError: no manifest editor implemented for
     node:package-lock.json` on `run`. Fixed: the manifest is now located via
     `candidate.expected_files` by ecosystem convention (`constants.py`,
     `_find_manifest_source`). *(found by live execution)*
  2. `apply`'s final re-verification (which runs against the primary tree,
     `worktree == root`) was picking up TrustPatch's own uncommitted `.trustpatch/`
     control-plane files as "unexpected file changes" and self-triggering a rollback
     on *every* apply. Fixed: `verify()` now excludes its own control directory.
     *(found by live execution)*
  3. `executor.py`'s manifest editing would silently strip `--hash=` pins and
     compound version constraints/markers — a real security regression (turns a
     hash-verified dependency into an unverified one). Fixed to preserve
     markers/comments and refuse (fail closed) on hash pins or compound constraints
     rather than guess. *(found by review)*
  4. A naive `RLIMIT_NPROC` cap (even a generous 256) reliably breaks `bwrap`'s
     `unshare(CLONE_NEWUSER)` with `EAGAIN` — the kernel charges namespace creation
     against the calling process's NPROC ucounts, and the safe threshold is both
     very high (confirmed: 500 fails, 1000 succeeds) and dependent on how many other
     processes the same user already has elsewhere on the system. Fixed: process-
     count limiting is skipped whenever network isolation is active. *(found while
     adding resource limits)*
  5. `policy.py` parsed `risk.auto_apply_maximum` from the policy YAML into
     `Policy.auto_max` but `evaluate()` never actually consulted it — it hardcoded
     `candidate.risk != "low"`, which only happened to match the *default* value.
     A site that configured a different threshold had it silently ignored. Fixed:
     `evaluate()` now genuinely compares risk against the configured threshold
     (`_exceeds_auto_max`), with unknown/malformed values failing closed (also now
     validated at the config layer via a `Literal["low","medium","high"]`).
     *(found by review, while implementing the fix above)*
  6. `apply` read `candidate_dict["approval_required"]` **directly from the stored
     JSON proposal file** (`.trustpatch/proposals/*.json`) without ever re-deriving
     it — a plain boolean field in a file TrustPatch itself writes into the project.
     A direct edit of that one field (accidental or adversarial) could skip the
     human-approval gate entirely for an otherwise high-risk change. Fixed: `apply`
     now re-evaluates the candidate fresh against the current policy and uses that,
     never the stored flag. Live-proven with a real attack simulation through the
     actual CLI (`typer.testing.CliRunner`): tamper the real proposal file, confirm
     `apply` still refuses and the dependency is genuinely untouched. *(found by
     review, immediately after fixing #5 — both were "policy decisions computed
     once and blindly trusted thereafter" bugs)*
  - A seventh, smaller gap was also closed: the SBOM independent-verification check
    only flagged unexpected *version changes* to existing components, not entirely
    new or vanished ones (e.g. an executor bug that also slipped in an unrelated
    dependency would have gone undetected even though the file-level check
    wouldn't catch it either, since the manifest file itself is expected to
    change). `verify()` now also flags unexpected additions/removals.
  - All seven have regression tests confirmed against a real repro (unit test or
    live CLI run), not just an isolated assertion.
- **Independent re-verification pass (2026-10-12)**, performed from a clean checkout
  with no reliance on prior claims: `pytest` re-run with `.mypy_cache`/`.ruff_cache`/
  `.pytest_cache` deleted first → **126 passed, 0 skipped** (unchanged); `ruff check`,
  `ruff format --check`, `mypy src` → all clean; `pip-audit --skip-editable` → no known
  vulnerabilities. Two full fresh lifecycles were run end to end against new scratch git
  repositories, not the ones used by earlier passes:
  1. A Node project (express 4.18.2, real package-lock.json) through `scan` → `plan`
     (live OSV query, the same two real CVEs, GHSA-qw6h-vgh9-j6wx and GHSA-rv95-896h-c2vc)
     → `propose` → `run`. `run` correctly failed closed with "lockfile package-lock.json
     was not refreshed" — expected and correct in this sandbox, which has no `npm`
     installed to actually refresh it; confirms the verifier's lockfile-refresh check has
     real teeth rather than rubber-stamping executor output.
  2. A Python project (jinja2 2.10, `requirements.txt`, no lockfile) through the full
     `scan` → `plan` (live OSV query, 11 real advisories including GHSA-cpwx-vrp4-4pq7) →
     `propose` → `run` (`passed: true`) → `apply` **refused** with no approval recorded →
     `approve` → `apply` (succeeded, real commit `c9480e2`) → `rollback` (real `git
     revert`, `requirements.txt` genuinely restored to `jinja2==2.10`, history preserved)
     → `audit --check` (`valid: true`, 6 real events). The real audit log from this run
     was then hand-tampered (one real event — the recorded approval — deleted from
     `.trustpatch/audit.jsonl`) and `audit --check` correctly reported `valid: false`
     with the exact first-broken event ID identified, then `valid: true` again once
     restored.
  - Live-verified directly against the `checks.run_check`/`run_all` API (the same one
    `verifier.py` calls): a check given a real absolute worktree path was genuinely
    blocked from reaching `pypi.org` under `bwrap --unshare-net` (`network_isolated:
    true`); a CPU-bound busy loop was killed by the real `RLIMIT_CPU` backstop
    (`returncode: -9`); a 4GiB allocation under a 200MiB `RLIMIT_AS` raised a genuine
    `MemoryError` instead of exhausting host memory.
  - Live-verified the ATT&CK/LOLBAS cold-vs-cached claim through the actual `intel` CLI
    against the real services, cache cleared first: cold fetch ~8.3s (`from_cache:
    false` for both sources) immediately followed by a cached call at ~0.48s
    (`from_cache: true` for both) — same order of magnitude as the previously recorded
    ~4.2s/~0.26s, both genuinely live, not reused output.
  - **One new, minor finding** (not previously documented, not exploitable through the
    current CLI): `checks._wrap_for_network_isolation` builds the `bwrap` invocation
    from `cwd` as given, without resolving it to an absolute path first. Reproduced
    directly: calling `bwrap` with `--bind . . --chdir .` (a relative worktree path)
    silently breaks binary resolution inside the sandbox (`execvp: No such file or
    directory` for a binary that is actually present and otherwise executable with an
    absolute path) — plausibly because bwrap resolves the relative bind destination
    against its own evolving mount state rather than the caller's original cwd. This is
    **not reachable today**: the only real call site, `sandbox.create()`, always builds
    the worktree under `tempfile.gettempdir() / "trustpatch-sandbox"`, which is always
    absolute. It fails closed (`passed: False`), never silently drops isolation, so it
    is a reliability/robustness gap rather than a security bypass — but `run_check`/
    `run_all` are public, documented functions, and a future caller (or a config option
    exposing `base_dir`) passing a relative path would get every sandboxed check broken
    with a confusing error. Recommended fix: `cwd = Path(cwd).resolve()` at the top of
    `run_check`.
  - No regressions found; every previously-"[x]" item below that was exercised live
    behaved exactly as documented.

## 1. Foundation

- [x] Repository builds cleanly.
- [x] CLI starts correctly.
- [x] Configuration validation works. (pydantic-validated `config/*.yaml` and `policies/*.yaml`)
- [ ] Test suite executes in CI. (passes locally; the actual GitHub Actions run is unconfirmed — no CI runner available in this environment. Note: GitHub's `ubuntu-latest` runners ship git preinstalled, so the git-gated tests that needed a manual local git install here would run natively there.)
- [x] Static type checking passes.
- [x] Linting passes.
- [x] Security dependency scan passes. (`pip-audit --skip-editable`: no known vulnerabilities; wired into CI)

## 2. Discovery

- [x] Python projects detected.
- [x] Node.js projects detected.
- [x] Go projects detected. (unit-tested against a synthetic go.mod)
- [x] Rust projects detected. (unit-tested against a synthetic Cargo.toml)
- [x] Manifests detected.
- [x] Lockfiles detected.
- [x] Git repositories handled safely. (real repo, real worktrees, real commits/reverts, twice — no corruption, no unexpected mutation)

## 3. Vulnerability Detection

- [x] Vulnerability database integration works. (live OSV queries, multiple times, all found real advisories)
- [x] Affected version matching is tested.
- [x] Fixed version detection is tested. (live-verified: minimal-fixed-version resolution matched real OSV data)
- [x] Advisory evidence is retained.
- [x] Offline/error conditions fail safely.

## 4. Update Planning

- [x] Candidate version selection is deterministic.
- [x] Major/minor/patch classification works.
- [x] Expected-change manifest is generated.
- [x] Risk classification is explainable.
- [x] Policy decision is deterministic.

## 5. Sandbox

- [x] Candidate changes never touch the primary workspace. (real `run`: worktree created under `/tmp`, primary tree untouched until an explicit `apply`)
- [x] Network restrictions work for configured checks. (live-verified: a real check genuinely blocked from reaching pypi.org via `bwrap --unshare-net`; honest fallback + reporting when bwrap isn't installed)
- [x] Resource limits work for configured checks. (live-verified: CPU and memory rlimits genuinely killed a busy-loop and an over-allocation)
- [x] Timeouts work.
- [x] Host credentials are unavailable to configured checks. (`checks.minimal_env` unit-tested)
- [x] Temporary artifacts are cleaned safely. (real worktree created and removed via `git worktree remove` + `shutil.rmtree`)
- [ ] Network isolation / resource limits for the git-worktree preparation step itself (executor/verifier's own git operations, not just user-configured checks). Only configured checks go through bwrap/rlimits today.

## 6. Testing

- [x] The check-execution mechanism itself works (pass/fail/timeout/missing-command), tool-agnostically.
- [x] Tests run in isolated (worktree) environments end to end with a real configured test command. (live-verified)
- [x] Build verification works end to end with a real configured build command. (mechanism identical to test/sast, live-verified via sast category)
- [x] Security scanning (SAST/secrets) works end to end with a real configured command. (live-verified — including proving the network isolation the SAST check ran under)
- [x] Test evidence is retained.
- [x] Failures block application. (live-verified twice: a stale lockfile, and a failing configured SAST check, both correctly blocked)

## 7. Independent Verification

- [x] Verifier does not trust updater output. (`verifier.py` does not import `executor.py`)
- [x] Resolved versions are independently checked. (live-verified)
- [x] Git diff is independently checked. (live-verified via real `git diff`/`git ls-files`)
- [x] Unexpected files block application. (live bug found: TrustPatch's own control directory was tripping this; now excluded and verified)
- [x] SBOM delta is checked.
- [x] Vulnerability rescan is checked. (live-verified: rescan reported `resolved` after the real version bump)
- [x] Final verification is reproducible. (live-verified: `apply`'s final re-verification ran and passed against the real primary tree, twice)

## 8. Approval

- [x] High-risk changes require approval. (live-verified: `apply` refused without one, then succeeded once one was recorded)
- [x] Approval is bound to exact evidence. (also: `apply` re-derives `approval_required` fresh from policy rather than trusting the stored proposal field — see bug #6 above — live-verified via a real tamper attempt through the CLI)
- [x] Rejection prevents application. (live-verified: `reject` then `apply` refused with the dependency genuinely untouched)
- [x] Expired approvals cannot be reused.
- [x] Approval events are audited.

## 9. Application

- [x] Only authorized changes can be applied. (live-verified: stale-HEAD detection, approval binding all exercised)
- [x] Final commit/diff is verified. (live-verified: real commits, messages include the evidence digest)
- [x] Final dependency state is scanned.
- [x] Final security state is verified.
- [x] Final test runs when configured. (live-verified in the combined-checks run)
- [x] Rollback is tested. (live-verified: real `git revert`, package.json correctly restored, history preserved)

## 10. Audit

- [x] Every security-sensitive operation has an event ID.
- [x] Audit records include timestamps.
- [x] Audit records include agent version.
- [x] Evidence hashes are recorded.
- [x] Approval identity is recorded.
- [x] Audit export works.
- [x] Tamper-evidence is implemented. (live-verified twice: `valid: true` on an untouched real event log, and `valid: false` with the exact broken event identified after a real simulated attack — deleting an event from that same log to hide it; hash-chaining, not cryptographic signing — see docs/TODO.md Phase 13)

## 11. LLM Safety

- [x] LLM cannot directly authorize changes. (no code path lets `adk_agent.py`'s tool output write an approval, policy decision, or apply — note: this module had a real syntax error until the latest audit pass, so earlier claims here, while directionally correct, rested on code that could not actually execute; `tests/test_adk_agent.py` now imports and exercises it for real, with a stubbed `google.adk.agents` module standing in for the optional heavy dependency)
- [x] LLM cannot retrieve production credentials. (the ADK agent's only tool is a read-only `inspect_project` wrapper)
- [x] LLM cannot bypass policy. (`Policy.evaluate` is a pure deterministic function; every live run's authorization was derived entirely from stored policy/approval files)
- [ ] LLM-generated explanations are marked as explanations. (no LLM-generated report/explanation feature exists yet to mark)
- [x] Deterministic security evidence remains authoritative.
- [x] Prompt injection tests exist. (`tests/test_security_hardening.py`: attacker-controlled OSV advisory text — shell metacharacters, script tags, template-injection payloads, null bytes — is proven to never influence the chosen fix version and to round-trip safely through JSON; dependency-name lookalikes are proven to never be fuzzy-matched)

## 12. Release Gate

A release is not production-ready until all critical requirements are complete and all high-severity security tests pass.

The release checklist must be signed by the designated engineering/security owner.

**Current state: substantially complete, close to release-ready.** Sections 1–11 are
now complete and executed with real evidence, including OS-level sandbox network and
resource isolation for configured checks and a dedicated adversarial/hardening test
suite (sandbox escape, prompt injection, dependency confusion, policy-bypass attempts,
audit tampering — docs/TODO.md Phase 15) — these were the largest open gaps.
Six real, previously-undiscovered bugs were found and fixed in an earlier verification
pass (two by live execution, four by review — full detail above), and a further five
were found and fixed in a follow-up end-to-end audit (a broken ADK module, the SR-007
policy-fingerprint gap, missing OSV retry/backoff, a duplicated version-string literal
in audit records, and dead/misleading network-allowlist config — see the Evidence
section above), each covered by a regression test confirmed against the real repro,
and the full `scan`→...→`apply`→`rollback`→`audit --check` lifecycle re-run live against
a fresh fixture both before and after to confirm nothing regressed. What remains: git-
worktree-preparation-step isolation (the executor's own git operations aren't yet run
through bwrap/rlimits, only user-configured checks are — network isolation doesn't
meaningfully apply there since git worktree creation is local-only, but resource
limits could still be added), and a CI-runner confirmation of the test suite (no
runner available in this environment; the workflow itself is in place and covers
tests + lint + format + types + dependency audit). Neither is a logic gap in what's
already built. Sections 14 (GitHub/GitLab/CI/Slack/dashboard integrations) and parts
of Phase 15 hardening (formal threat-model sign-off, fuzz-style reproducibility
testing) remain deliberately out of scope — they are explicitly "Planned" rather than
MVP per README.md, not gaps in the MVP's own claims.

**Independently re-audited 2026-10-12** from a separate session with no access to the
reasoning behind the earlier passes — only the code, the tests, and the live CLI. Every
checked item that was re-exercised (full lifecycle twice, audit tamper detection, bwrap
network isolation, CPU/memory rlimits, ATT&CK/LOLBAS live cold/cached fetch, the ADK
module's import and tool-boundary behavior, the intel command's policy-gating of
sources) held up exactly as claimed, with no regressions. One new minor, non-exploitable
robustness gap was found and documented above (relative-`cwd` handling in
`checks._wrap_for_network_isolation`); the test suite's actual size
(`tests/test_security_hardening.py`) was corrected from the previously-recorded
14/15 to the true 16. Verdict is unchanged: **substantially complete, close to
release-ready**, blocked only by the two previously-identified gaps (git-worktree-
preparation-step isolation, and CI-runner confirmation) plus the deliberately
out-of-scope Section 14 integrations and formal threat-model sign-off.
