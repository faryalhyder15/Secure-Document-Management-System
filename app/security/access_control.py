"""
app/security/access_control.py
==============================
THE single place where authorization decisions are made
(Part 1.3, Part 2 "Document-level access control", Part 3 scenarios 1, 2, 5, 6).

Hybrid model:
  1. RBAC (Role-Based) for SYSTEM actions
        system_role = 'user'  -> can use documents
        system_role = 'admin' -> can additionally manage users, read the audit
                                 log and run storage integrity scans.
     Admin does NOT get any automatic document access (least privilege /
     separation of duties) — and cannot get it cryptographically either,
     because no document key is wrapped for the admin.

  2. DAC (Discretionary) for DOCUMENT actions
        The document owner decides who gets which document role:
           owner  > editor > viewer
     stored in the `document_permissions` table.

  3. ABAC-style attribute conditions checked on EVERY request
        * account must be active
        * permission must not be expired (expires_at)
        * document must exist

Every document route calls `authorize_document()` BEFORE doing anything.
Hiding a button in the UI is NOT relied on — the server always checks.

Anti-enumeration: "document does not exist" and "you have no access" give the
SAME 404 response, so an attacker changing IDs (scenario 2) cannot even learn
whether a document ID is valid.
"""
from datetime import datetime, timezone

from . import audit

# --------------------------------------------------------------------------
# Permission matrix: action -> which document roles may perform it
# --------------------------------------------------------------------------
DOCUMENT_ACTIONS = {
    "read":     {"owner", "editor", "viewer"},   # view details, download
    "verify":   {"owner", "editor", "viewer"},   # integrity check
    "update":   {"owner", "editor"},             # upload a new version
    "share":    {"owner"},                       # grant access
    "revoke":   {"owner"},                       # remove access
    "delete":   {"owner"},                       # delete document
    "view_acl": {"owner"},                       # see who has access
}

SYSTEM_ACTIONS = {
    "manage_users":    {"admin"},
    "view_audit":      {"admin"},
    "verify_audit":    {"admin"},
    "integrity_scan":  {"admin"},
}


class AccessDenied(Exception):
    """Raised when a permission check fails. `status` is the HTTP code to use."""

    def __init__(self, message="Access denied", status=403):
        super().__init__(message)
        self.status = status


def _is_expired(expires_at) -> bool:
    """True if the grant has expired. Malformed timestamps are treated as
    expired (fail closed) so a DB-write attacker cannot crash the app or
    bypass the check by writing garbage into the column."""
    if not expires_at:
        return False
    try:
        return datetime.fromisoformat(expires_at) <= datetime.now(timezone.utc)
    except (ValueError, TypeError):
        # FIX: fail closed — treat unparseable expiry as expired.
        try:
            audit.record("security.malformed_expiry", "denied", target_type="system",
                         details={"value": str(expires_at)[:64]})
        except Exception:
            # Never let audit failure change the authorization outcome
            pass
        return True


def get_document_role(conn, user_id: str, document_id: str):
    """Return 'owner'/'editor'/'viewer' or None (no row, or row expired)."""
    row = conn.execute(
        "SELECT role, expires_at FROM document_permissions WHERE document_id = ? AND user_id = ?",
        (document_id, user_id)).fetchone()
    if row is None or _is_expired(row["expires_at"]):
        return None
    return row["role"]


def authorize_document(conn, user, document_id: str, action: str) -> str:
    """Check that `user` may perform `action` on `document_id`.

    Returns the user's document role on success.
    Raises AccessDenied (404 for "no access at all", 403 for "has access but
    not enough") and writes an audit record on every denial.
    """
    if action not in DOCUMENT_ACTIONS:
        raise ValueError(f"unknown action {action}")   # programming error -> fail closed

    if user is None or not user["is_active"]:
        raise AccessDenied("Login required", 401)

    doc = conn.execute("SELECT id FROM documents WHERE id = ?", (document_id,)).fetchone()
    role = get_document_role(conn, user["id"], document_id) if doc else None

    if role is None:
        # Same response whether the doc exists or not (prevents ID probing)
        audit.record("document.access_denied", "denied", target_type="document",
                     target_id=document_id,
                     details={"action": action, "reason": "no permission" if doc else "no such document"})
        raise AccessDenied("Document not found", 404)

    if role not in DOCUMENT_ACTIONS[action]:
        audit.record("document.access_denied", "denied", target_type="document",
                     target_id=document_id, details={"action": action, "role": role,
                                                     "reason": "insufficient document role"})
        raise AccessDenied(f"Your role '{role}' does not allow '{action}' on this document", 403)

    return role


def authorize_system(user, action: str) -> None:
    """RBAC check for administrator functions."""
    if action not in SYSTEM_ACTIONS:
        raise ValueError(f"unknown system action {action}")
    if user is None:
        raise AccessDenied("Login required", 401)
    if user["system_role"] not in SYSTEM_ACTIONS[action]:
        audit.record("admin.access_denied", "denied", target_type="system",
                     details={"action": action, "role": user["system_role"]})
        raise AccessDenied("Administrator privileges required", 403)