# TrustPatch Security Update Agent

TrustPatch is a **fail-closed defensive-security maintenance agent**. It discovers a project, inventories dependencies, records evidence, classifies update risk, and keeps human approval between analysis and mutation. The first working slice is intentionally conservative: it can scan Python and Node.js projects, generate a local plan, write append-only audit events, and expose safe adapters for MITRE ATT&CK, LOLBAS, and VirusTotal.

## Defensive-security tools

| Source | Purpose | Trust boundary |
|---|---|---|
| MITRE ATT&CK | Map observed defensive findings and behaviors to techniques from the official STIX dataset. | Read-only intelligence; never an approval signal. |
| LOLBAS | Identify Windows living-off-the-land binaries and scripts relevant to suspicious execution context. | Read-only enrichment; command examples are not executed. |
| VirusTotal | Optional hash reputation lookup using `VIRUSTOTAL_API_KEY`. | Disabled without an explicit key; no uploads are performed by the MVP. |

These sources complement dependency maintenance: ATT&CK provides behavior context, LOLBAS provides defensive detection context, and VirusTotal provides optional file reputation. Vulnerability status and dependency resolution remain deterministic code paths; LLM explanations are non-authoritative.

## Quick start

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
trustpatch scan ./examples/node-fixture
trustpatch plan ./examples/node-fixture
trustpatch audit ./examples/node-fixture
pytest
```

The CLI never modifies the target project during `scan` or `plan`. It writes evidence under `.trustpatch/`, which is the intended local control-plane directory. The production-ready next step is to add isolated Git worktrees, package-manager-specific updates, independent verification, approval records, and final apply/rollback commands exactly as specified in `docs/AGENT-INSTRUCTION.md` and `docs/TODOFINISH.md`.

## Google ADK

Install the optional extra with `pip install -e '.[adk]'`. `trustpatch.adk_agent.build_agent()` creates an ADK agent whose only project-inspection tool returns deterministic facts. The ADK agent is instructed to explain evidence and never authorize changes. If ADK is unavailable, all deterministic CLI functionality still works.

## Security posture

No production credentials are read. VirusTotal uses an environment variable only when explicitly configured. No package installation, build, test, or project lifecycle script is executed by the scan/plan MVP. A future executor must use a disposable worktree and a restricted sandbox before running untrusted package code. Any ambiguous verification must block application.
