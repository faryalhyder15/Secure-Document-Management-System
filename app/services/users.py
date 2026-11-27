"""
app/services/users.py
=====================
User identity management & authentication (Part 2 "User identity management
and authentication", Part 1.3 Q1).

Features:
  * register      -> username/password policy, scrypt hash, key pairs, recovery code
  * authenticate  -> constant-ish time check, account lockout after 5 failures,
                     generic error message (no username enumeration)
  * change_password -> needs current password, re-wraps private keys,
                       ends all other sessions
  * recover_account -> recovery code unlocks keys, sets new password
  * admin functions -> enable/disable, change system role
"""
import re
import uuid
from datetime import datetime, timezone

from flask import current_app

from ..db import transaction
from ..security import audit, crypto, keystore, sessions

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
# A tiny deny-list; a real system would use the "Have I Been Pwned" k-anonymity API.
COMMON_PASSWORDS = {"password123", "1234567890", "qwertyuiop", "password1!", "iloveyou12",
                    "admin12345", "welcome123", "letmein123", "abcdefghij", "pakistan123"}


class UserError(Exception):
    """User-facing validation / authentication error."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cfg(name):
    return current_app.config[name]


def validate_password(password: str, username: str) -> None:
    """Basic password policy (length over complexity, per NIST SP 800-63B)."""
    if len(password) < _cfg("PASSWORD_MIN_LENGTH"):
        raise UserError(f"Password must be at least {_cfg('PASSWORD_MIN_LENGTH')} characters.")
    if len(password) > 128:
        raise UserError("Password is too long (max 128).")
    if password.lower() in COMMON_PASSWORDS:
        raise UserError("This password is too common.")
    if username.lower() in password.lower():
        raise UserError("Password must not contain the username.")


def register(conn, username: str, password: str, system_role: str = "user"):
    """Create a user. Returns (user_id, recovery_code)."""
    username = (username or "").strip()
    if not USERNAME_RE.match(username):
        raise UserError("Username: 3-32 chars, letters/digits/._- only.")
    validate_password(password, username)
    if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        raise UserError("That username is not available.")

    user_id = str(uuid.uuid4())
    keys = keystore.create_user_keys(user_id, password, _cfg("SERVER_SECRETS")["server_kek"],
                                     _cfg("SCRYPT_N"))
    now = _now()
    conn.execute(
        """INSERT INTO users (id, username, password_hash, system_role, enc_public_key,
           sign_public_key, key_salt, private_keys_pw, private_keys_rec, created_at, password_changed_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (user_id, username, crypto.hash_password(password, _cfg("SCRYPT_N")), system_role,
         keys["enc_public_key"], keys["sign_public_key"], keys["key_salt"],
         keys["private_keys_pw"], keys["private_keys_rec"], now, now))
    audit.record("user.register", target_type="user", target_id=user_id,
                 actor={"id": user_id, "username": username}, details={"system_role": system_role})
    return user_id, keys["recovery_code"]


def authenticate(conn, username: str, password: str):
    """Verify credentials. Returns (user_row, unlocked_keys) or raises UserError.

    The SAME generic message is used for "no such user" and "wrong
    password" so attackers cannot discover valid usernames."""
    generic = "Invalid username or password."
    user = conn.execute("SELECT * FROM users WHERE username = ?", ((username or "").strip(),)).fetchone()

    if user is None:
        # Burn similar CPU time as a real check to reduce timing differences
        crypto.verify_password(password, crypto.hash_password("dummy-password", _cfg("SCRYPT_N")))
        audit.record("auth.login", "failure", target_type="user",
                     details={"username_attempted": username, "reason": "unknown user"})
        raise UserError(generic)

    actor = {"id": user["id"], "username": user["username"]}
    if not user["is_active"]:
        audit.record("auth.login", "denied", target_type="user", target_id=user["id"], actor=actor,
                     details={"reason": "account disabled"})
        raise UserError("This account is disabled. Contact an administrator.")

    if user["locked_until"] and datetime.fromisoformat(user["locked_until"]) > datetime.now(timezone.utc):
        audit.record("auth.login", "denied", target_type="user", target_id=user["id"], actor=actor,
                     details={"reason": "account locked"})
        raise UserError("Account temporarily locked after too many failed attempts. Try later.")

    if not crypto.verify_password(password, user["password_hash"]):
        failed = user["failed_logins"] + 1
        locked_until = None
        if failed >= _cfg("LOCKOUT_THRESHOLD"):
            locked_until = (datetime.now(timezone.utc) + _cfg("LOCKOUT_DURATION")).isoformat()
            failed = 0
        conn.execute("UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
                     (failed, locked_until, user["id"]))
        audit.record("auth.login", "failure", target_type="user", target_id=user["id"], actor=actor,
                     details={"reason": "bad password"})
        if locked_until:
            audit.record("auth.lockout", "success", target_type="user", target_id=user["id"],
                         actor=actor, details={"locked_until": locked_until})
        raise UserError(generic)

    # Password correct -> unlock private keys into memory
    keys = keystore.unlock_with_password(user, password, _cfg("SERVER_SECRETS")["server_kek"],
                                         _cfg("SCRYPT_N"))
    conn.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (user["id"],))
    audit.record("auth.login", "success", target_type="user", target_id=user["id"], actor=actor)
    return user, keys


def change_password(conn, user, current_session_hash: str, keys, old_password: str, new_password: str):
    """Returns the NEW recovery code (old one stops working)."""
    if not crypto.verify_password(old_password, user["password_hash"]):
        audit.record("auth.password_change", "failure", target_type="user", target_id=user["id"],
                     details={"reason": "wrong current password"})
        raise UserError("Current password is incorrect.")
    # FIX (security review item #4): reject a no-op "change" to the same
    # password. Otherwise the recovery code is needlessly rotated and the
    # old code silently stops working with zero user benefit.
    if old_password == new_password:
        raise UserError("New password must be different from the current password.")
    validate_password(new_password, user["username"])
    wrapped = keystore.rewrap_keys(user["id"], keys, new_password,
                                   _cfg("SERVER_SECRETS")["server_kek"], _cfg("SCRYPT_N"))
    with transaction(conn):
        conn.execute(
            """UPDATE users SET password_hash = ?, key_salt = ?, private_keys_pw = ?, private_keys_rec = ?,
               password_changed_at = ? WHERE id = ?""",
            (crypto.hash_password(new_password, _cfg("SCRYPT_N")), wrapped["key_salt"],
             wrapped["private_keys_pw"], wrapped["private_keys_rec"], _now(), user["id"]))
        # Credential change => kill every OTHER session (attacker may hold one)
        sessions.destroy_all_sessions_for_user(conn, user["id"], except_hash=current_session_hash)
    audit.record("auth.password_change", target_type="user", target_id=user["id"])
    return wrapped["recovery_code"]


def recover_account(conn, username: str, recovery_code: str, new_password: str):
    """Forgotten password: recovery code unlocks keys; returns new recovery code."""
    user = conn.execute("SELECT * FROM users WHERE username = ?", ((username or "").strip(),)).fetchone()
    generic = "Recovery failed. Check the username and recovery code."
    if user is None or not user["is_active"]:
        audit.record("auth.recovery", "failure", details={"username_attempted": username})
        raise UserError(generic)
    actor = {"id": user["id"], "username": user["username"]}
    try:
        keys = keystore.unlock_with_recovery_code(user, recovery_code, _cfg("SERVER_SECRETS")["server_kek"])
    except crypto.IntegrityError:
        audit.record("auth.recovery", "failure", target_type="user", target_id=user["id"], actor=actor,
                     details={"reason": "bad recovery code"})
        raise UserError(generic)
    validate_password(new_password, user["username"])
    wrapped = keystore.rewrap_keys(user["id"], keys, new_password,
                                   _cfg("SERVER_SECRETS")["server_kek"], _cfg("SCRYPT_N"))
    with transaction(conn):
        conn.execute(
            """UPDATE users SET password_hash = ?, key_salt = ?, private_keys_pw = ?, private_keys_rec = ?,
               password_changed_at = ?, failed_logins = 0, locked_until = NULL WHERE id = ?""",
            (crypto.hash_password(new_password, _cfg("SCRYPT_N")), wrapped["key_salt"],
             wrapped["private_keys_pw"], wrapped["private_keys_rec"], _now(), user["id"]))
        sessions.destroy_all_sessions_for_user(conn, user["id"])
    audit.record("auth.recovery", target_type="user", target_id=user["id"], actor=actor)
    return wrapped["recovery_code"]


# ---------------------------------------------------------------- admin ops
def set_active(conn, admin, target_id: str, active: bool):
    if target_id == admin["id"]:
        raise UserError("You cannot disable your own account.")
    with transaction(conn):
        cur = conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (1 if active else 0, target_id))
        if cur.rowcount == 0:
            raise UserError("No such user.")
        if not active:
            sessions.destroy_all_sessions_for_user(conn, target_id)  # immediate effect
    audit.record("admin.user_enable" if active else "admin.user_disable", target_type="user",
                 target_id=target_id)


def set_system_role(conn, admin, target_id: str, role: str):
    if role not in ("user", "admin"):
        raise UserError("Invalid role.")
    if target_id == admin["id"]:
        raise UserError("You cannot change your own role.")
    with transaction(conn):
        cur = conn.execute("UPDATE users SET system_role = ? WHERE id = ?", (role, target_id))
        if cur.rowcount == 0:
            raise UserError("No such user.")
        sessions.destroy_all_sessions_for_user(conn, target_id)  # re-login with new role
    audit.record("admin.role_change", target_type="user", target_id=target_id, details={"new_role": role})