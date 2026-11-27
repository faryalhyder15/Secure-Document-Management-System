"""
app/services/documents.py
=========================
All document operations. EVERY public function here starts with an
authorization check (access_control.authorize_document) — there is no code
path that touches a document without one.

ENCRYPTION FLOW (envelope encryption, see docs/05_cryptographic_design.md):

  upload:  plaintext --AES-256-GCM(DEK, AAD="doc:<id>:v<version>")--> blob on disk
           filename  --AES-256-GCM(DEK, AAD="meta:<id>")-------------> documents.enc_metadata
           DEK       --RSA-OAEP(owner public key)--------------------> document_keys row
           SHA-256(plaintext) --Ed25519(uploader signing key)--------> documents.signature

  download: check permission -> unwrap DEK with user's private key (RAM) ->
            decrypt (GCM tag check = tamper detection) -> verify signature ->
            stream to user from memory (no temp file on disk).

  share:   owner unwraps DEK, re-wraps it with the RECIPIENT's public key.
  revoke:  delete recipient's permission + wrapped key, then RE-KEY: new DEK,
           re-encrypt blob, re-wrap for the remaining users. A recipient who
           cached the old DEK can no longer decrypt the new blob.
"""
import json
import uuid
from datetime import datetime, timedelta, timezone

from flask import current_app, g

from ..db import transaction
from ..security import audit, crypto
from ..security.access_control import AccessDenied, authorize_document

ROLES_GRANTABLE = ("viewer", "editor")      # 'owner' can never be granted


class DocumentError(Exception):
    """User-facing error (bad input, integrity failure ...)."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _store():
    return current_app.config["BLOB_STORE"]


def _blob_aad(doc_id: str, version: int) -> bytes:
    # Binds the ciphertext to THIS document and THIS version.
    return f"securedms|doc:{doc_id}|v{version}".encode()


def _meta_aad(doc_id: str) -> bytes:
    return f"securedms|meta:{doc_id}".encode()


def _signed_message(doc_id: str, version: int, plaintext_sha256: str) -> bytes:
    return f"securedms|sig|{doc_id}|{version}|{plaintext_sha256}".encode()


def _sanitize_filename(name: str) -> str:
    """Keep only a safe base name (no paths, no control characters)."""
    name = (name or "document").replace("\\", "/").split("/")[-1]
    name = "".join(ch for ch in name if ch.isprintable() and ch not in '<>:"|?*')
    return name.strip()[:150] or "document"


def _get_user_dek(conn, doc_id: str, user, keys) -> bytes:
    """Unwrap this document's key using the CALLER's private key."""
    row = conn.execute("SELECT wrapped_dek FROM document_keys WHERE document_id = ? AND user_id = ?",
                       (doc_id, user["id"])).fetchone()
    if row is None:
        # Has an ACL row but no key (should not happen) -> fail closed
        raise AccessDenied("Document not found", 404)
    return crypto.rsa_unwrap(keys.enc_private, row["wrapped_dek"])


def _decrypt_metadata(doc_row, dek) -> dict:
    return json.loads(crypto.aead_decrypt(dek, doc_row["enc_metadata"], _meta_aad(doc_row["id"])))


# =============================================================================
# CREATE
# =============================================================================
def upload(conn, user, keys, filename: str, mimetype: str, data: bytes) -> str:
    if not data:
        raise DocumentError("Empty files are not allowed.")
    doc_id = str(uuid.uuid4())
    version = 1
    dek = crypto.new_aes_key()                                    # fresh random key per document
    blob_name = _store().new_blob_name()

    ciphertext = crypto.aead_encrypt(dek, data, _blob_aad(doc_id, version))
    meta = json.dumps({"filename": _sanitize_filename(filename),
                       "mimetype": (mimetype or "application/octet-stream")[:100]}).encode()
    enc_metadata = crypto.aead_encrypt(dek, meta, _meta_aad(doc_id))
    plain_hash = crypto.sha256_hex(data)
    signature = crypto.sign(keys.sign_private, _signed_message(doc_id, version, plain_hash))
    wrapped = crypto.rsa_wrap(user["enc_public_key"], dek)
    now = _now()

    _store().write(blob_name, ciphertext)
    try:
        with transaction(conn):
            conn.execute(
                """INSERT INTO documents (id, owner_id, blob_name, enc_metadata, plaintext_size,
                   ciphertext_sha256, signature, signed_by, version, key_generation, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (doc_id, user["id"], blob_name, enc_metadata, len(data), crypto.sha256_hex(ciphertext),
                 signature, user["id"], version, 1, now, now))
            conn.execute("INSERT INTO document_permissions (document_id, user_id, role, granted_by, granted_at)"
                         " VALUES (?,?,?,?,?)", (doc_id, user["id"], "owner", user["id"], now))
            conn.execute("INSERT INTO document_keys (document_id, user_id, wrapped_dek, key_generation)"
                         " VALUES (?,?,?,?)", (doc_id, user["id"], wrapped, 1))
            conn.execute("INSERT INTO document_history (document_id, version, changed_by, change_type,"
                         " ciphertext_sha256, created_at) VALUES (?,?,?,?,?,?)",
                         (doc_id, version, user["id"], "upload", crypto.sha256_hex(ciphertext), now))
    except Exception:
        _store().delete(blob_name)   # don't leave orphan ciphertext behind
        raise
    audit.record("document.upload", target_type="document", target_id=doc_id,
                 details={"size_bytes": len(data)})   # NOTE: filename deliberately not logged
    return doc_id


# =============================================================================
# READ
# =============================================================================
def list_for_user(conn, user, keys) -> list:
    """Documents the user can access (own + shared, not expired)."""
    rows = conn.execute(
        """SELECT d.*, p.role, p.expires_at, u.username AS owner_name
           FROM document_permissions p
           JOIN documents d ON d.id = p.document_id
           JOIN users u ON u.id = d.owner_id
           WHERE p.user_id = ? ORDER BY d.updated_at DESC""", (user["id"],)).fetchall()
    out = []
    now = datetime.now(timezone.utc)
    for r in rows:
        if r["expires_at"] and datetime.fromisoformat(r["expires_at"]) <= now:
            continue  # expired grants are invisible
        try:
            meta = _decrypt_metadata(r, _get_user_dek(conn, r["id"], user, keys))
            name = meta["filename"]
        except (crypto.IntegrityError, AccessDenied):
            name = "[metadata unreadable - possible tampering]"
            # FIX (security review item #6): audit the first time this session
            # sees a document whose metadata no longer decrypts. Without this
            # an attacker tampering with metadata leaves no trail in the log.
            notified = getattr(g, "_tampered_notified", None)
            if notified is None:
                notified = g._tampered_notified = set()
            if r["id"] not in notified:
                notified.add(r["id"])
                audit.record("document.metadata_integrity_failure", "failure",
                             target_type="document", target_id=r["id"])
        out.append({"id": r["id"], "filename": name, "role": r["role"], "owner": r["owner_name"],
                    "size": r["plaintext_size"], "version": r["version"], "updated_at": r["updated_at"],
                    "expires_at": r["expires_at"]})
    return out


def get_details(conn, user, keys, doc_id: str) -> dict:
    role = authorize_document(conn, user, doc_id, "read")
    doc = conn.execute("SELECT d.*, u.username AS owner_name, s.username AS signer_name FROM documents d "
                       "JOIN users u ON u.id = d.owner_id JOIN users s ON s.id = d.signed_by "
                       "WHERE d.id = ?", (doc_id,)).fetchone()
    dek = _get_user_dek(conn, doc_id, user, keys)
    meta = _decrypt_metadata(doc, dek)
    details = {"id": doc_id, "filename": meta["filename"], "mimetype": meta["mimetype"], "role": role,
               "owner": doc["owner_name"], "size": doc["plaintext_size"], "version": doc["version"],
               "key_generation": doc["key_generation"], "signed_by": doc["signer_name"],
               "created_at": doc["created_at"], "updated_at": doc["updated_at"],
               "ciphertext_sha256": doc["ciphertext_sha256"]}
    if role == "owner":   # only owners see the ACL (need-to-know)
        details["acl"] = [dict(r) for r in conn.execute(
            """SELECT u.username, p.user_id, p.role, p.granted_at, p.expires_at FROM document_permissions p
               JOIN users u ON u.id = p.user_id WHERE p.document_id = ? ORDER BY p.role""", (doc_id,))]
    details["history"] = [dict(r) for r in conn.execute(
        """SELECT h.version, h.change_type, h.created_at, u.username FROM document_history h
           JOIN users u ON u.id = h.changed_by WHERE h.document_id = ? ORDER BY h.id DESC""", (doc_id,))]
    return details


def _decrypt_and_verify(conn, doc, dek) -> bytes:
    """Decrypt blob + verify signature. Raises IntegrityError on ANY tampering."""
    if not _store().exists(doc["blob_name"]):
        raise crypto.IntegrityError("encrypted file is missing from storage")
    blob = _store().read(doc["blob_name"])
    plaintext = crypto.aead_decrypt(dek, blob, _blob_aad(doc["id"], doc["version"]))  # GCM tag check
    signer = conn.execute("SELECT sign_public_key FROM users WHERE id = ?", (doc["signed_by"],)).fetchone()
    msg = _signed_message(doc["id"], doc["version"], crypto.sha256_hex(plaintext))
    if not crypto.verify_signature(signer["sign_public_key"], doc["signature"], msg):
        raise crypto.IntegrityError("digital signature invalid")
    return plaintext


def download(conn, user, keys, doc_id: str):
    """Returns (filename, data). Decryption happens in memory only."""
    authorize_document(conn, user, doc_id, "read")
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    dek = _get_user_dek(conn, doc_id, user, keys)
    try:
        data = _decrypt_and_verify(conn, doc, dek)
    except crypto.IntegrityError as exc:
        audit.record("document.integrity_failure", "failure", target_type="document", target_id=doc_id,
                     details={"stage": "download", "error": str(exc)})
        raise DocumentError("INTEGRITY CHECK FAILED: this document was modified outside the application. "
                            "Download blocked.") from exc
    meta = _decrypt_metadata(doc, dek)
    audit.record("document.download", target_type="document", target_id=doc_id,
                 details={"version": doc["version"]})
    return meta["filename"], data


def verify(conn, user, keys, doc_id: str) -> dict:
    """User-triggered integrity check. Returns a step-by-step report."""
    authorize_document(conn, user, doc_id, "verify")
    doc = conn.execute("SELECT d.*, s.username AS signer FROM documents d JOIN users s ON s.id = d.signed_by"
                       " WHERE d.id = ?", (doc_id,)).fetchone()
    dek = _get_user_dek(conn, doc_id, user, keys)
    report = {"blob_present": _store().exists(doc["blob_name"]), "ciphertext_hash_ok": False,
              "aead_tag_ok": False, "signature_ok": False, "signed_by": doc["signer"]}
    if report["blob_present"]:
        blob = _store().read(doc["blob_name"])
        report["ciphertext_hash_ok"] = crypto.sha256_hex(blob) == doc["ciphertext_sha256"]
        try:
            plaintext = crypto.aead_decrypt(dek, blob, _blob_aad(doc_id, doc["version"]))
            report["aead_tag_ok"] = True
            signer = conn.execute("SELECT sign_public_key FROM users WHERE id = ?", (doc["signed_by"],)).fetchone()
            report["signature_ok"] = crypto.verify_signature(
                signer["sign_public_key"], doc["signature"],
                _signed_message(doc_id, doc["version"], crypto.sha256_hex(plaintext)))
            report["plaintext_sha256"] = crypto.sha256_hex(plaintext)
        except crypto.IntegrityError:
            pass
    report["intact"] = all(report[k] for k in ("blob_present", "ciphertext_hash_ok", "aead_tag_ok", "signature_ok"))
    audit.record("document.verify", "success" if report["intact"] else "failure", target_type="document",
                 target_id=doc_id, details={"intact": report["intact"]})
    return report


# =============================================================================
# UPDATE (new version)
# =============================================================================
def update(conn, user, keys, doc_id: str, filename: str, mimetype: str, data: bytes) -> int:
    authorize_document(conn, user, doc_id, "update")
    if not data:
        raise DocumentError("Empty files are not allowed.")
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    dek = _get_user_dek(conn, doc_id, user, keys)
    # Refuse to build on top of a tampered document
    try:
        _decrypt_and_verify(conn, doc, dek)
    except crypto.IntegrityError as exc:
        audit.record("document.integrity_failure", "failure", target_type="document", target_id=doc_id,
                     details={"stage": "update", "error": str(exc)})
        raise DocumentError("Current version failed its integrity check; update refused.") from exc

    version = doc["version"] + 1
    new_blob = _store().new_blob_name()
    ciphertext = crypto.aead_encrypt(dek, data, _blob_aad(doc_id, version))
    meta = json.dumps({"filename": _sanitize_filename(filename),
                       "mimetype": (mimetype or "application/octet-stream")[:100]}).encode()
    signature = crypto.sign(keys.sign_private, _signed_message(doc_id, version, crypto.sha256_hex(data)))
    now = _now()
    _store().write(new_blob, ciphertext)
    with transaction(conn):
        conn.execute("""UPDATE documents SET blob_name = ?, enc_metadata = ?, plaintext_size = ?,
                        ciphertext_sha256 = ?, signature = ?, signed_by = ?, version = ?, updated_at = ?
                        WHERE id = ?""",
                     (new_blob, crypto.aead_encrypt(dek, meta, _meta_aad(doc_id)), len(data),
                      crypto.sha256_hex(ciphertext), signature, user["id"], version, now, doc_id))
        conn.execute("INSERT INTO document_history (document_id, version, changed_by, change_type,"
                     " ciphertext_sha256, created_at) VALUES (?,?,?,?,?,?)",
                     (doc_id, version, user["id"], "update", crypto.sha256_hex(ciphertext), now))
    _store().delete(doc["blob_name"])
    audit.record("document.update", target_type="document", target_id=doc_id,
                 details={"new_version": version, "size_bytes": len(data)})
    return version


# =============================================================================
# DELETE
# =============================================================================
def delete(conn, user, doc_id: str) -> None:
    authorize_document(conn, user, doc_id, "delete")
    doc = conn.execute("SELECT blob_name FROM documents WHERE id = ?", (doc_id,)).fetchone()
    with transaction(conn):
        # ON DELETE CASCADE removes permissions, wrapped keys and history.
        # Deleting the wrapped keys = crypto-shredding: even a backup copy of
        # the blob can never be decrypted again.
        conn.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
    _store().delete(doc["blob_name"])
    audit.record("document.delete", target_type="document", target_id=doc_id)


# =============================================================================
# SHARE
# =============================================================================
def share(conn, user, keys, doc_id: str, target_username: str, role: str, expires_days=None) -> None:
    authorize_document(conn, user, doc_id, "share")
    if role not in ROLES_GRANTABLE:
        raise DocumentError("Role must be 'viewer' or 'editor'.")
    target = conn.execute("SELECT * FROM users WHERE username = ?", ((target_username or "").strip(),)).fetchone()
    if target is None or not target["is_active"]:
        raise DocumentError("No active user with that username.")
    if target["id"] == user["id"]:
        raise DocumentError("You already own this document.")

    expires_at = None
    if expires_days:
        days = int(expires_days)
        if not 1 <= days <= current_app.config["MAX_SHARE_DAYS"]:
            raise DocumentError(f"Expiry must be 1-{current_app.config['MAX_SHARE_DAYS']} days.")
        expires_at = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()

    # FIX (security review item #5): read key_generation AND unwrap the DEK
    # *inside* the transaction so a concurrent revoke() (which re-keys the
    # document) cannot race us into writing a wrapped key for a stale DEK.
    with transaction(conn):
        doc = conn.execute("SELECT key_generation FROM documents WHERE id = ?", (doc_id,)).fetchone()
        dek = _get_user_dek(conn, doc_id, user, keys)
        wrapped = crypto.rsa_wrap(target["enc_public_key"], dek)   # only recipient can unwrap
        conn.execute("""INSERT INTO document_permissions (document_id, user_id, role, granted_by, granted_at, expires_at)
                        VALUES (?,?,?,?,?,?)
                        ON CONFLICT(document_id, user_id) DO UPDATE SET role = excluded.role,
                        granted_by = excluded.granted_by, granted_at = excluded.granted_at,
                        expires_at = excluded.expires_at""",
                     (doc_id, target["id"], role, user["id"], _now(), expires_at))
        conn.execute("""INSERT INTO document_keys (document_id, user_id, wrapped_dek, key_generation)
                        VALUES (?,?,?,?) ON CONFLICT(document_id, user_id) DO UPDATE SET
                        wrapped_dek = excluded.wrapped_dek, key_generation = excluded.key_generation""",
                     (doc_id, target["id"], wrapped, doc["key_generation"]))
    audit.record("document.share", target_type="document", target_id=doc_id,
                 details={"grantee": target["username"], "role": role, "expires_at": expires_at})


# =============================================================================
# REVOKE (+ re-key)
# =============================================================================
def revoke(conn, user, keys, doc_id: str, target_user_id: str) -> None:
    authorize_document(conn, user, doc_id, "revoke")
    perm = conn.execute("SELECT p.role, u.username FROM document_permissions p JOIN users u ON u.id = p.user_id"
                        " WHERE p.document_id = ? AND p.user_id = ?", (doc_id, target_user_id)).fetchone()
    if perm is None:
        raise DocumentError("That user has no access to this document.")
    if perm["role"] == "owner":
        raise DocumentError("The owner's access cannot be revoked.")

    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    old_dek = _get_user_dek(conn, doc_id, user, keys)
    try:
        plaintext = _decrypt_and_verify(conn, doc, old_dek)
    except crypto.IntegrityError as exc:
        raise DocumentError("Document failed its integrity check; cannot re-key.") from exc

    # ---- RE-KEY: new DEK, new blob, new wrapped keys for remaining users ----
    new_dek = crypto.new_aes_key()
    new_gen = doc["key_generation"] + 1
    new_blob = _store().new_blob_name()
    ciphertext = crypto.aead_encrypt(new_dek, plaintext, _blob_aad(doc_id, doc["version"]))
    meta_plain = crypto.aead_decrypt(old_dek, doc["enc_metadata"], _meta_aad(doc_id))
    remaining = conn.execute(
        """SELECT p.user_id, u.enc_public_key FROM document_permissions p JOIN users u ON u.id = p.user_id
           WHERE p.document_id = ? AND p.user_id != ?""", (doc_id, target_user_id)).fetchall()
    _store().write(new_blob, ciphertext)
    now = _now()
    with transaction(conn):
        conn.execute("DELETE FROM document_permissions WHERE document_id = ? AND user_id = ?", (doc_id, target_user_id))
        conn.execute("DELETE FROM document_keys WHERE document_id = ?", (doc_id,))
        for r in remaining:
            conn.execute("INSERT INTO document_keys (document_id, user_id, wrapped_dek, key_generation) VALUES (?,?,?,?)",
                         (doc_id, r["user_id"], crypto.rsa_wrap(r["enc_public_key"], new_dek), new_gen))
        conn.execute("""UPDATE documents SET blob_name = ?, enc_metadata = ?, ciphertext_sha256 = ?,
                        key_generation = ?, updated_at = ? WHERE id = ?""",
                     (new_blob, crypto.aead_encrypt(new_dek, meta_plain, _meta_aad(doc_id)),
                      crypto.sha256_hex(ciphertext), new_gen, now, doc_id))
        conn.execute("INSERT INTO document_history (document_id, version, changed_by, change_type,"
                     " ciphertext_sha256, created_at) VALUES (?,?,?,?,?,?)",
                     (doc_id, doc["version"], user["id"], "rekey", crypto.sha256_hex(ciphertext), now))
    _store().delete(doc["blob_name"])
    audit.record("document.revoke", target_type="document", target_id=doc_id,
                 details={"revoked_user": perm["username"], "previous_role": perm["role"],
                          "new_generation": new_gen})


# =============================================================================
# ADMIN: storage integrity scan WITHOUT decryption (least privilege)
# =============================================================================
def integrity_scan(conn) -> list:
    """Compare every blob's SHA-256 with the value recorded at write time.
    Admin learns 'intact / modified / missing' but never the contents."""
    results = []
    for d in conn.execute("SELECT d.id, d.blob_name, d.ciphertext_sha256, u.username AS owner "
                          "FROM documents d JOIN users u ON u.id = d.owner_id"):
        if not _store().exists(d["blob_name"]):
            status = "MISSING"
        elif crypto.sha256_hex(_store().read(d["blob_name"])) != d["ciphertext_sha256"]:
            status = "MODIFIED"
        else:
            status = "OK"
        results.append({"id": d["id"], "owner": d["owner"], "status": status})
    bad = [r for r in results if r["status"] != "OK"]
    audit.record("admin.integrity_scan", "success" if not bad else "failure", target_type="system",
                 details={"checked": len(results), "problems": len(bad)})
    return results