# Defensive-security integration guide

## Design principle

TrustPatch treats security intelligence as **read-only evidence and context**. None of the three sources can authorize a dependency update, approve a candidate, or trigger execution. The deterministic policy engine and independent verifier remain the only authority for those decisions.

## MITRE ATT&CK

The adapter reads the official Enterprise ATT&CK STIX bundle and filters active `attack-pattern` objects. For a production deployment, replace the moving `master` URL with a pinned release from the official `attack-stix-data` repository or use the official TAXII 2.1 service at `https://attack-taxii.mitre.org`. Cache collection metadata, honor pagination, use bounded retries, and record the exact release and retrieval timestamp. ATT&CK is useful for mapping defensive observations to techniques, data sources, detections, and coverage gaps.

ATT&CK descriptions and references are untrusted content. They must be escaped before display and must never be interpreted as commands. A mapping is a review aid, not proof that a dependency or process is malicious.

## LOLBAS

The adapter reads the official static JSON feed at `https://lolbas-project.github.io/api/lolbas.json`. The feed is best used to enrich process telemetry, correlate `MitreID` fields, and surface relevant detection guidance. Production code should validate the top-level array, cache a last-known-good snapshot, use atomic replacement, and expose a stale-data indicator when offline.

**Never execute or replay command examples from LOLBAS.** They are attacker-relevant examples and may include destructive, remote, or exfiltration behavior. A LOLBin name alone is not a maliciousness verdict; detection must use context such as parent process, path, user, privilege, baseline, and network behavior.

## VirusTotal

The adapter performs an optional hash-first report lookup against VirusTotal API v3. It reads `VIRUSTOTAL_API_KEY` only from the environment and performs no file or URL uploads. Without a key, the result is explicitly `not_configured`; this is not a clean or safe verdict. Production use must add bounded retries for transient errors, quota-aware throttling, caching, stale-result handling, and audit fields for indicator, timestamp, source, and API outcome.

Do not submit or query confidential, proprietary, or personal indicators through an unapproved public service. VirusTotal results are analyst enrichment, not sole proof of safety. Keep the API key out of logs and use approved private scanning when data policy requires it.

## Combined command

```bash
trustpatch intel ./project
trustpatch intel ./project --sha256 <64-hex-digest>
```

The command is read-only with respect to the project. It records a structured audit event and reports each source independently, so an unavailable source does not become a false positive or false negative. A production release should fail closed for automated apply decisions when required evidence is unavailable.

## Authoritative references

- [Google ADK](https://adk.dev/) — agent framework and safety guidance.
- [MITRE ATT&CK data and tools](https://attack.mitre.org/resources/attack-data-and-tools/).
- [LOLBAS API](https://lolbas-project.github.io/api/).
- [VirusTotal API v3 overview](https://docs.virustotal.com/reference/overview).
