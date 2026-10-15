from __future__ import annotations
from pathlib import Path
import yaml
from .models import Candidate

DEFAULT_REQUIRED = {"major_version", "cryptography", "authentication", "database", "native_library", "runtime_security_dependency", "build_toolchain", "ci_security", "infrastructure", "low_confidence"}

class Policy:
    def __init__(self, path: Path | None = None):
        self.data = yaml.safe_load(path.read_text()) if path and path.exists() else {}
        approval = self.data.get("approval", {})
        self.required_for = set(approval.get("required_for", DEFAULT_REQUIRED))
        self.fail_closed = bool(self.data.get("risk", {}).get("fail_closed", True))
        self.auto_max = self.data.get("risk", {}).get("auto_apply_maximum", "low")

    def evaluate(self, candidate: Candidate) -> Candidate:
        name = candidate.dependency.name.lower()
        reasons = list(candidate.risk_reasons)
        if candidate.advisories: reasons.append("known vulnerability evidence exists")
        if any(token in name for token in ("auth", "oauth", "jwt", "crypto", "openssl", "bcrypt")):
            reasons.append("security-sensitive dependency")
        if any(token in name for token in ("sql", "postgres", "mysql", "redis", "mongo")):
            reasons.append("database dependency")
        major = self._major(candidate.dependency.version) != self._major(candidate.proposed_version)
        if major: reasons.append("major version change")
        candidate.risk_reasons = sorted(set(reasons))
        candidate.risk = "high" if len(reasons) >= 2 or major else ("medium" if reasons else "low")
        categories = set()
        if major: categories.add("major_version")
        if any("security-sensitive" in r for r in reasons): categories.update({"authentication", "cryptography", "runtime_security_dependency"})
        if any("database" in r for r in reasons): categories.add("database")
        if not candidate.advisories and candidate.proposed_version == "*": categories.add("low_confidence")
        candidate.approval_required = bool(categories & self.required_for) or candidate.risk != "low"
        return candidate

    @staticmethod
    def _major(version: str) -> str:
        return version.lstrip("v").split(".")[0] if version not in ("*", "") else "*"
