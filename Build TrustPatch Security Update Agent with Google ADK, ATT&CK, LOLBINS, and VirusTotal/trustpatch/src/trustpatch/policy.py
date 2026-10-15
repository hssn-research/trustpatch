from __future__ import annotations

from pathlib import Path

from .audit import digest
from .config import DEFAULT_APPROVAL_REQUIRED, load_policy_file
from .models import Candidate
from .versions import is_major_change

DEFAULT_REQUIRED = set(DEFAULT_APPROVAL_REQUIRED)

_RISK_ORDER = {"low": 0, "medium": 1, "high": 2}


def _exceeds_auto_max(risk: str, auto_max: str) -> bool:
    """Fail closed on an unrecognized risk/auto_max value: treat it as maximal
    risk so an unexpected string never accidentally grants automatic apply."""
    return _RISK_ORDER.get(risk, 2) > _RISK_ORDER.get(auto_max, 0)


class Policy:
    def __init__(self, path: Path | None = None):
        """Load and validate a policy YAML file (SR-007: an unrecognized key or
        malformed value fails loudly via pydantic rather than being silently
        ignored, which could otherwise leave the policy weaker than intended)."""
        parsed = load_policy_file(path)
        self.required_for = set(parsed.approval.required_for)
        self.fail_closed = parsed.risk.fail_closed
        self.auto_max = parsed.risk.auto_apply_maximum
        self.require_lockfile_refresh = parsed.execution.require_lockfile_refresh
        self.sources = parsed.sources
        # SR-007: a content fingerprint of the exact policy that produced this
        # Policy instance. `propose` records it on the proposal; `apply` refuses
        # to proceed if the policy file at the same --policy path has changed in
        # the meantime (e.g. loosening `required_for` or raising
        # `auto_apply_maximum` between review and apply) — closing the gap where
        # agent execution could otherwise silently inherit a weakened
        # authorization policy. Computed from the *parsed* model, not raw file
        # bytes, so a comment-only edit does not force a spurious re-proposal.
        self.fingerprint = digest(parsed.model_dump(mode="json"))

    def evaluate(self, candidate: Candidate) -> Candidate:
        name = candidate.dependency.name.lower()
        reasons = list(candidate.risk_reasons)
        if candidate.advisories:
            reasons.append("known vulnerability evidence exists")
        if any(token in name for token in ("auth", "oauth", "jwt", "crypto", "openssl", "bcrypt")):
            reasons.append("security-sensitive dependency")
        if any(token in name for token in ("sql", "postgres", "mysql", "redis", "mongo")):
            reasons.append("database dependency")
        major = is_major_change(candidate.dependency.version, candidate.proposed_version)
        if major:
            reasons.append("major version change")
        if candidate.confidence != "confirmed":
            reasons.append("low confidence assessment")
        candidate.risk_reasons = sorted(set(reasons))
        candidate.risk = "high" if len(reasons) >= 2 or major else ("medium" if reasons else "low")
        categories = set()
        if major:
            categories.add("major_version")
        if any("security-sensitive" in r for r in reasons):
            categories.update({"authentication", "cryptography", "runtime_security_dependency"})
        if any("database" in r for r in reasons):
            categories.add("database")
        if not candidate.advisories and candidate.proposed_version == "*":
            categories.add("low_confidence")
        if candidate.confidence != "confirmed":
            categories.add("low_confidence")
        candidate.approval_required = bool(categories & self.required_for) or _exceeds_auto_max(
            candidate.risk, self.auto_max
        )
        return candidate
