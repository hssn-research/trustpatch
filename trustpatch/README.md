# TrustPatch Security Update Agent

TrustPatch is a **fail-closed defensive-security maintenance agent**. It discovers a project, inventories dependencies, checks them against trusted vulnerability intelligence (OSV), classifies update risk, prepares candidate updates in a disposable git worktree, independently verifies them, requires explicit human approval for high-risk changes, and applies only authorized changes — with automatic rollback if a post-apply verification fails. It supports Python, Node.js, Go, and Rust dependency inventories, and exposes read-only adapters for MITRE ATT&CK, LOLBAS, and VirusTotal.

## Defensive-security tools

| Source | Purpose | Trust boundary |
|---|---|---|
| MITRE ATT&CK | Map observed defensive findings and behaviors to techniques from a pinned Enterprise ATT&CK STIX release. | Read-only intelligence; never an approval signal. |
| LOLBAS | Identify Windows living-off-the-land binaries and scripts relevant to suspicious execution context. | Read-only enrichment; command examples are not executed. |
| VirusTotal | Optional hash reputation lookup using `VIRUSTOTAL_API_KEY`. | Disabled without an explicit key; no uploads are performed. |

These sources complement dependency maintenance: ATT&CK provides behavior context, LOLBAS provides defensive detection context, and VirusTotal provides optional file reputation. Vulnerability status and dependency resolution remain deterministic code paths; LLM explanations are non-authoritative — this boundary is enforced structurally (`tests/test_security_hardening.py::test_decision_modules_never_import_the_intel_sources`), not just documented.

All three are bounded-retry, cached under `.trustpatch/cache/` (a cold ATT&CK fetch is ~4s for the real pinned release; a cached one is ~0.25s), and individually gated by `sources.mitre_attack`/`lolbas`/`virustotal` in the policy file — set one to `false` to hard-disable that query path entirely (no network call happens). See `docs/DEFENSIVE_SECURITY.md` for the full detail per source.

```bash
trustpatch intel ./project --policy policies/default.yaml
trustpatch intel ./project --sha256 <64-hex-digest> --policy policies/default.yaml
```

## Quick start

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest

trustpatch scan ./examples/node-fixture     # inventory only, read-only
trustpatch plan ./examples/node-fixture     # OSV vulnerability check, read-only
trustpatch audit ./examples/node-fixture    # append-only audit log
```

`scan` and `plan` never modify the target project; evidence is written under `.trustpatch/` inside it.

### Full lifecycle (requires the target to be a git repository)

`propose` → `run` → `approve`/`reject` → `apply` → `rollback` mutate a project, so each
step past `plan` requires the target to be a git repo (worktree isolation, diff-based
verification, and `git revert`-based rollback all depend on it):

```bash
trustpatch propose ./my-project --update-id upd_express
trustpatch run ./my-project --update-id upd_express          # disposable git worktree + independent verification
trustpatch verify ./my-project --update-id upd_express        # show the verification report
trustpatch approve upd_express ./my-project --actor alice --reason "fixes GHSA-..."
trustpatch apply ./my-project --update-id upd_express         # mutates the primary tree only if authorized
trustpatch rollback ./my-project --update-id upd_express      # git revert, if ever needed
trustpatch audit ./my-project --check                         # verify the audit log's tamper-evident hash chain
```

`run` never mutates the primary tree — it prepares and verifies in an isolated worktree
and always cleans it up. `apply` refuses to run on any ambiguous, missing, or failed
evidence, and auto-rolls-back if final post-apply verification fails.

### Sandbox isolation for configured checks

Beyond git-worktree filesystem isolation and credential-environment scrubbing,
configured `checks.*` commands (see below) also get, live-verified:

- **Real network isolation** (SR-003) via a genuine network namespace (`--unshare-net`)
  when [`bwrap`](https://github.com/containers/bubblewrap) (bubblewrap) is installed —
  this works unprivileged even under Ubuntu 24.04+'s AppArmor restrictions on
  unprivileged user namespaces, because distros allowlist the bwrap binary
  specifically. Falls back to no isolation, honestly, when bwrap isn't installed
  — `CheckResult.network_isolated` always reflects what actually happened; never
  claimed when it wasn't applied.
- **Real CPU and memory limits** (SR-004) via unprivileged `setrlimit` (`checks.ResourceLimits`,
  defaults: 120 CPU-seconds, 2 GiB address space). A configurable process-count limit
  (`max_processes`) exists too, but is automatically skipped whenever network isolation
  (bwrap) is active — the kernel charges `unshare(CLONE_NEWUSER)` against the calling
  process's `RLIMIT_NPROC`, so a naive process-count cap unpredictably breaks the very
  isolation it's meant to complement (confirmed: as low as 500 can fail it, and the safe
  threshold depends on the machine's overall load, not just this check's own processes).

Still not implemented: cgroup-based disk-I/O isolation, and general OS-level isolation
for the git-worktree preparation step itself (only configured checks go through bwrap
today — see `docs/TODO.md` Phase 8 for the full tracked list).

### Other known limitations (see `docs/TODO.md` for the full tracked list)

- The executor edits manifest files only; it never runs a package manager, so a
  lockfile is not regenerated automatically (the verifier fails closed on that by
  default — see `policies/default.yaml`'s `execution.require_lockfile_refresh`).
- `checks.test`/`build`/`sast`/`secrets` are opt-in, user-configured commands — TrustPatch
  never claims a check passed unless it actually ran.

## Google ADK

Install the optional extra with `pip install -e '.[adk]'`. `trustpatch.adk_agent.build_agent()` creates an ADK agent whose only project-inspection tool returns deterministic facts. The ADK agent is instructed to explain evidence and never authorize changes. If ADK is unavailable, all deterministic CLI functionality still works.

## Security posture

No production credentials are read. VirusTotal uses an environment variable only when explicitly configured. No package installation, build, test, or project lifecycle script is executed by the scan/plan MVP. A future executor must use a disposable worktree and a restricted sandbox before running untrusted package code. Any ambiguous verification must block application.
