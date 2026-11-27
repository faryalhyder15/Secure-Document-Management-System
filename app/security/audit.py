"""
app/security/audit.py
=====================
Tamper-evident audit trail (Part 1.5, Part 2 "audit trail", Part 3 scenario 7).

FOUR layers of protection for audit records:

  Layer 1  SQLite triggers reject every UPDATE / DELETE on audit_log
           (see schema.sql). Stops the application itself, or anyone using
           normal SQL, from changing history.

  Layer 2  HASH CHAIN. Each record stores
               entry_hash = SHA-256( prev_hash || canonical_json(record) )
           Changing or deleting any record breaks every hash after it.

  Layer 3  HMAC. entry_mac = HMAC-SHA256(audit_key, entry_hash).
           Someone who edits a row AND recomputes the hash chain still cannot
           produce valid MACs without the audit key (kept in secrets/, not in
           the DB).

  Layer 4  EXTERNAL ANCHOR. After every write the newest (seq, entry_hash)
           is copied to audit_anchor/head.json (outside the DB). Deleting the
           LAST few rows (truncation) — which a chain alone cannot reveal —
           is detected because the DB no longer reaches the anchored head.

WHAT IS LOGGED: who, what, when, from where (IP / user-agent), target,
outcome (success / denied / failure) and small non-secret details.
WHAT IS NEVER LOGGED: passwords, recovery codes, keys, session tokens or
document contents. `_redact()` enforces this even if a caller makes a mistake.

Design rule: audit records are written on their OWN database connection and
never inside another transaction. So a denied/failed operation that rolls
back still leaves its audit record behind.
"""
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from flask import current_app, g, has_request_context, request

from .. import db as dbmod
from . import crypto

GENESIS_HASH = "0" * 64              # prev_hash of the very first record
_WRITE_LOCK = threading.Lock()       # serialise appends inside this process

# Keys whose VALUES must never reach the log
_SENSITIVE_WORDS = ("password", "secret", "token", "key", "recovery", "content", "csrf")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _redact(details: dict) -> dict:
    """Remove anything that looks like a secret from `details`."""
    clean = {}
    for k, v in (details or {}).items():
        if any(word in k.lower() for word in _SENSITIVE_WORDS):
            clean[k] = "[REDACTED]"
        else:
            clean[k] = v if isinstance(v, (int, float, bool)) or v is None else str(v)[:200]
    return clean


def _canonical(record: dict) -> bytes:
    """Deterministic byte representation of the fields covered by the hash."""
    fields = ("seq", "ts", "actor_id", "actor_username", "action", "target_type",
              "target_id", "outcome", "ip_address", "user_agent", "details")
    return json.dumps({f: record[f] for f in fields}, sort_keys=True,
                      separators=(",", ":")).encode()


def compute_entry_hash(prev_hash: str, record: dict) -> str:
    return crypto.sha256_hex(prev_hash.encode() + _canonical(record))


# ----------------------------------------------------------------------------
# Anchor file helpers (layer 4)
# ----------------------------------------------------------------------------
def _write_anchor(path: Path, seq: int, entry_hash: str, audit_key: bytes) -> None:
    """Atomically write the anchor.

    FIX (security review item #3): flush + fsync the temp file before
    os.replace() and fsync the parent directory afterwards. Without this a
    crash between the DB commit and the anchor write leaves the anchor one
    record behind the DB, causing a *false* truncation alarm on the next
    verification run.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"seq": seq, "entry_hash": entry_hash,
               "mac": crypto.hmac_sha256_hex(audit_key, f"{seq}|{entry_hash}".encode()),
               "updated_at": _now()}
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, indent=2))
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)  # atomic on POSIX
    # FIX: also fsync the directory so the rename itself is durable.
    try:
        dir_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        # Some filesystems (e.g. Windows) do not support directory fsync;
        # the file-level fsync above already gives us atomic durability there.
        pass


def _read_anchor(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text())


# ----------------------------------------------------------------------------
# Writing records
# ----------------------------------------------------------------------------
def record(action: str, outcome: str = "success", *, target_type: str = None,
           target_id: str = None, details: dict = None, actor=None) -> None:
    """Append one audit record. Safe to call from any route/service.

    `actor` may be a user row/dict; by default the logged-in user (g.user).
    """
    app = current_app
    if actor is None and has_request_context():
        actor = getattr(g, "user", None)
    ip = request.remote_addr if has_request_context() else None
    ua = (request.headers.get("User-Agent", "")[:200] if has_request_context() else "system")

    rec = {
        "ts": _now(),
        "actor_id": actor["id"] if actor else None,
        "actor_username": actor["username"] if actor else None,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "outcome": outcome,
        "ip_address": ip,
        "user_agent": ua,
        "details": json.dumps(_redact(details or {}), sort_keys=True),
    }
    audit_key = app.config["SERVER_SECRETS"]["audit_hmac"]

    with _WRITE_LOCK:
        conn = dbmod.connect(app.config["DATABASE_PATH"])  # own connection (see docstring)
        try:
            with dbmod.transaction(conn):
                last = conn.execute(
                    "SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
                prev_hash = last["entry_hash"] if last else GENESIS_HASH
                rec["seq"] = (last["seq"] + 1) if last else 1
                entry_hash = compute_entry_hash(prev_hash, rec)
                entry_mac = crypto.hmac_sha256_hex(audit_key, entry_hash.encode())
                conn.execute(
                    """INSERT INTO audit_log (seq, ts, actor_id, actor_username, action,
                       target_type, target_id, outcome, ip_address, user_agent, details,
                       prev_hash, entry_hash, entry_mac)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (rec["seq"], rec["ts"], rec["actor_id"], rec["actor_username"], action,
                     target_type, target_id, outcome, ip, ua, rec["details"],
                     prev_hash, entry_hash, entry_mac))
            # Only after a successful COMMIT do we move the anchor forward.
            _write_anchor(Path(app.config["AUDIT_ANCHOR_FILE"]), rec["seq"], entry_hash, audit_key)
        finally:
            conn.close()


# ----------------------------------------------------------------------------
# Verifying the whole log
# ----------------------------------------------------------------------------
def verify_chain(conn, audit_key: bytes, anchor_path) -> dict:
    """Walk every record and report any sign of tampering.

    Returns {"ok": bool, "checked": n, "problems": [str, ...]}.
    """
    problems = []
    prev_hash = GENESIS_HASH
    expected_seq = 1
    last_seq, last_hash = 0, GENESIS_HASH
    rows = conn.execute("SELECT * FROM audit_log ORDER BY seq ASC").fetchall()

    for row in rows:
        r = dict(row)
        if r["seq"] != expected_seq:
            problems.append(f"Missing record(s): expected seq {expected_seq}, found {r['seq']} "
                            f"(records deleted)")
        if r["prev_hash"] != prev_hash:
            problems.append(f"seq {r['seq']}: chain broken (prev_hash does not match previous record)")
        recomputed = compute_entry_hash(r["prev_hash"], r)
        if recomputed != r["entry_hash"]:
            problems.append(f"seq {r['seq']}: content was MODIFIED (hash mismatch)")
        expected_mac = crypto.hmac_sha256_hex(audit_key, r["entry_hash"].encode())
        if not crypto.constant_time_equal(expected_mac, r["entry_mac"]):
            problems.append(f"seq {r['seq']}: HMAC invalid (record forged or hash recomputed "
                            f"without the audit key)")
        prev_hash = r["entry_hash"]
        expected_seq = r["seq"] + 1
        last_seq, last_hash = r["seq"], r["entry_hash"]

    anchor = _read_anchor(Path(anchor_path))
    if anchor is None:
        if rows:
            problems.append("Anchor file missing - cannot rule out truncation of the log")
    else:
        anchor_mac = crypto.hmac_sha256_hex(audit_key, f"{anchor['seq']}|{anchor['entry_hash']}".encode())
        if not crypto.constant_time_equal(anchor_mac, anchor["mac"]):
            problems.append("Anchor file itself has been tampered with (bad MAC)")
        elif last_seq < anchor["seq"]:
            problems.append(f"Log TRUNCATED: anchor says last record is seq {anchor['seq']}, "
                            f"database ends at seq {last_seq}")
        elif last_seq == anchor["seq"] and last_hash != anchor["entry_hash"]:
            problems.append(f"Last record seq {last_seq} differs from anchored hash")

    return {"ok": not problems, "checked": len(rows), "problems": problems}