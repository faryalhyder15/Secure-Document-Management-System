"""
app/security/sessions.py
========================
Server-side session management + CSRF protection (Part 1.3 Q1, Part 1.4 hint
"session security").

Why server-side sessions instead of Flask's default signed-cookie session?
  * They can be REVOKED instantly (logout, admin disables user, password
    change kills all other sessions). A signed cookie stays valid until it
    expires.
  * The cookie contains only a random 256-bit token; no user data.
  * The DB stores only SHA-256(token) — a DB leak does not leak live sessions.

Cookie flags:
  HttpOnly  -> JavaScript cannot read it (limits XSS impact)
  SameSite=Strict -> browser does not send it on cross-site requests (CSRF)
  Secure    -> only sent over HTTPS (enabled when running with TLS)

Timeouts: idle 15 min, absolute 8 h (see config.py).

CSRF: each session has its own random csrf_token; every POST form must send
it back and it is compared in constant time.
"""
import secrets
from datetime import datetime, timezone

from flask import current_app, g, request

from . import crypto, keystore

COOKIE_NAME = "sdms_session"


def _now():
    return datetime.now(timezone.utc)


def _hash(token: str) -> str:
    return crypto.sha256_hex(token.encode())


def create_session(conn, user_id: str, unlocked_keys) -> str:
    """Start a NEW session after successful login.

    A brand-new token is generated every login -> prevents session fixation.
    Returns the raw token (goes into the cookie only)."""
    token = secrets.token_urlsafe(32)          # 256 bits of randomness
    token_hash = _hash(token)
    now = _now().isoformat()
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, last_seen, ip_address, user_agent)"
        " VALUES (?,?,?,?,?,?,?)",
        (token_hash, user_id, secrets.token_urlsafe(32), now, now,
         request.remote_addr, request.headers.get("User-Agent", "")[:200]))
    keystore.remember_keys(token_hash, unlocked_keys)  # private keys -> RAM only
    return token


def destroy_session(conn, token_hash: str) -> None:
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
    keystore.forget_keys(token_hash)


def destroy_all_sessions_for_user(conn, user_id: str, except_hash: str = None) -> None:
    """Used on password change / account disable / role change."""
    rows = conn.execute("SELECT token_hash FROM sessions WHERE user_id = ?", (user_id,)).fetchall()
    for r in rows:
        if r["token_hash"] != except_hash:
            destroy_session(conn, r["token_hash"])


def load_session(conn):
    """Called before every request. Sets g.user, g.session, g.keys or None.

    Returns a short reason string if a session existed but was ended
    (timeout etc.), so the UI can explain why the user was logged out."""
    g.user = g.session = g.keys = None
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    token_hash = _hash(token)
    row = conn.execute("SELECT * FROM sessions WHERE token_hash = ?", (token_hash,)).fetchone()
    if row is None:
        return None

    cfg = current_app.config
    now = _now()
    created = datetime.fromisoformat(row["created_at"])
    last_seen = datetime.fromisoformat(row["last_seen"])
    if now - last_seen > cfg["SESSION_IDLE_TIMEOUT"]:
        destroy_session(conn, token_hash)
        return "Your session expired after inactivity. Please log in again."
    if now - created > cfg["SESSION_ABSOLUTE_TIMEOUT"]:
        destroy_session(conn, token_hash)
        return "Your session reached its maximum lifetime. Please log in again."

    user = conn.execute("SELECT * FROM users WHERE id = ?", (row["user_id"],)).fetchone()
    if user is None or not user["is_active"]:
        destroy_session(conn, token_hash)
        return "Your account is disabled."

    keys = keystore.get_keys(token_hash)
    if keys is None:
        # e.g. server restarted -> keys are gone from RAM -> must log in again
        destroy_session(conn, token_hash)
        return "Please log in again to unlock your keys."

    conn.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (now.isoformat(), token_hash))
    g.user, g.session, g.keys = user, row, keys
    return None


def set_cookie(response, token: str) -> None:
    response.set_cookie(COOKIE_NAME, token, httponly=True, samesite="Strict",
                        secure=current_app.config["SESSION_COOKIE_SECURE"], path="/")


def clear_cookie(response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/")


def check_csrf() -> bool:
    """True if the submitted form token matches the session's token."""
    if g.get("session") is None:
        return False
    sent = request.form.get("csrf_token", "")
    return crypto.constant_time_equal(sent, g.session["csrf_token"])
