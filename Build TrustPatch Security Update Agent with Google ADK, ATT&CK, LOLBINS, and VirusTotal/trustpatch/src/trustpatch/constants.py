from __future__ import annotations

#: Name of TrustPatch's local control-plane directory (audit log, plans,
#: proposals, verifications, approvals, rollback records). Lives inside the
#: target project by convention. Never treated as part of a candidate's
#: expected or unexpected file changes — see verifier.py.
CONTROL_DIR_NAME = ".trustpatch"
