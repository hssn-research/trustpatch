# Defensive-security integration guide

## Design principle

TrustPatch treats security intelligence as **read-only evidence and context**. None of the three sources can authorize a dependency update, approve a candidate, or trigger execution. The deterministic policy engine and independent verifier remain the only authority for those decisions. This is enforced structurally, not just by convention: `tests/test_security_hardening.py::test_decision_modules_never_import_the_intel_sources` reads the actual source of `policy.py`, `planner.py`, `verifier.py`, and `executor.py` and fails if any of them ever reference `MitreAttackSource`, `LolbasSource`, or `VirusTotalSource`.

Each source is independently gated by `sources.mitre_attack`/`lolbas`/`virustotal` in the policy file passed to `trustpatch intel --policy <path>` (default `policies/default.yaml`, all three enabled). Setting one to `false` hard-disables that query path — no network call is made at all, live-verified by a test that fails if the network is touched while disabled.

## MITRE ATT&CK

The adapter reads a **pinned release** (`v19.2` by default — see `DEFAULT_ATTACK_RELEASE` in `src/trustpatch/integrations/sources.py`) from the official `attack-stix-data` repository, not the moving `master` branch, and filters active `attack-pattern` objects. Network requests use bounded retries (3 attempts, exponential backoff, honoring a server's `Retry-After` header on 429). The extracted techniques are cached locally under `.trustpatch/cache/mitre_attack.json` (the raw bundle is tens of megabytes; a cold fetch takes several seconds, a cached one is near-instant — both timings are live-verified in `tests/test_sources.py`). Every result, live or cached, carries the exact release and an ISO retrieval timestamp; if the live feed is unreachable, a cached snapshot is served with `stale: true` and `offline_fallback: true` rather than failing outright when one exists. ATT&CK is useful for mapping defensive observations to techniques, data sources, detections, and coverage gaps.

ATT&CK descriptions and references are untrusted content. The `intel` command only ever surfaces a technique *count* plus the release/timestamp metadata — raw ATT&CK narrative text is never included in CLI output or the audit trail, so there is nothing to escape or interpret as a command in the current surface.

## LOLBAS

The adapter reads the official static JSON feed at `https://lolbas-project.github.io/api/lolbas.json`. The feed is best used to enrich process telemetry, correlate `MitreID` fields, and surface relevant detection guidance. The top-level shape is strictly validated — a malformed feed (wrong type, non-object entries) raises clearly rather than silently behaving like "zero LOLBins", which would be indistinguishable from a genuinely empty result. A last-known-good snapshot is cached under `.trustpatch/cache/lolbas.json` via write-to-temp-then-atomic-rename (never a partially-written file), and served — marked `stale: true` — when the live feed is unreachable and a cache exists.

**Never execute or replay command examples from LOLBAS.** They are attacker-relevant examples and may include destructive, remote, or exfiltration behavior. A LOLBin name alone is not a maliciousness verdict; detection must use context such as parent process, path, user, privilege, baseline, and network behavior. The current `intel` surface only reports an entry *count*, never raw entries, so command text never reaches a shell or any execution path — enforced structurally the same way as the read-only decision boundary above.

## VirusTotal

The adapter performs an optional hash-first report lookup against VirusTotal API v3. It reads `VIRUSTOTAL_API_KEY` only from the environment and performs no file or URL uploads. Without a key, the result is explicitly `not_configured`; this is not a clean or safe verdict. Bounded retries (3 attempts, exponential backoff) handle transient 5xx errors; a 429 response honors `Retry-After` during retry and, if still rate-limited after retries are exhausted, falls back to a cached last-known result (marked stale) when one exists rather than failing outright. Results are cached per-indicator under `.trustpatch/cache/virustotal/<sha256>.json`. **Every** result — `not_configured`, `not_found`, `unavailable`, and `ok` alike — carries `indicator` (the queried hash), `timestamp`, `source: "virustotal"`, and an explicit `api_outcome` (`no_api_key` / `not_found` / `rate_limited` / `rate_limited_stale_cache_fallback` / `error_stale_cache_fallback` / `cache_hit` / `success`), so the audit trail never has to guess what actually happened.

Do not submit or query confidential, proprietary, or personal indicators through an unapproved public service. VirusTotal results are analyst enrichment, not sole proof of safety. The API key is read only from the environment and never appears in any result, log line, or cache file — verified by a test that asserts a distinctive fake key value is absent from the full serialized result. Use `sources.virustotal: false` in policy to hard-disable this query path entirely for indicators that must never leave the organization; use approved private scanning when data policy requires it.

## Combined command

```bash
trustpatch intel ./project --policy policies/default.yaml
trustpatch intel ./project --sha256 <64-hex-digest> --policy policies/default.yaml
```

The command is read-only with respect to the project. It records a structured audit event — including which `policy_path` governed the run, so a later reviewer can tell which `sources.*` toggles and thresholds were in effect — and reports each source independently, so an unavailable or policy-disabled source does not become a false positive or false negative. Automated apply decisions (`trustpatch apply`) never consult these sources at all (see the Design principle above), so there is no "required evidence unavailable" apply-blocking condition to fail closed on — the two are architecturally separate by construction, not by a runtime check.

## Authoritative references

- [Google ADK](https://adk.dev/) — agent framework and safety guidance.
- [MITRE ATT&CK data and tools](https://attack.mitre.org/resources/attack-data-and-tools/).
- [LOLBAS API](https://lolbas-project.github.io/api/).
- [VirusTotal API v3 overview](https://docs.virustotal.com/reference/overview).
