"""
tests/test_security_scenarios.py
================================
Automated versions of the SEVEN adversarial scenarios required by Part 3 of
the project manual. Each test = one scenario. Run:

    pytest -v tests/test_security_scenarios.py

(For a narrated, human-readable run with evidence output, use
 scripts/attack_demos.py.)
"""
import io
import json

from app.security import audit, crypto
from conftest import user_id


# ---------------------------------------------------------------------------
# Scenario 1 - Unauthorized document access
# ---------------------------------------------------------------------------
def test_s1_unauthorized_access_is_denied_and_logged(make_user, db):
    alice, mallory = make_user("alice"), make_user("mallory")
    doc = alice.upload(b"alice private")
    for url in (f"/documents/{doc}", f"/documents/{doc}/download"):
        r = mallory.c.get(url)
        assert r.status_code == 404 and b"alice private" not in r.data
    assert mallory.post(f"/documents/{doc}/verify").status_code == 404
    denied = db.execute("SELECT * FROM audit_log WHERE action='document.access_denied' AND actor_username='mallory'"
                        ).fetchall()
    assert len(denied) == 3


# ---------------------------------------------------------------------------
# Scenario 2 - Identifier manipulation (IDOR)
# ---------------------------------------------------------------------------
def test_s2_identifier_manipulation(make_user, db):
    alice, bob = make_user("alice"), make_user("bob")
    alice_doc = alice.upload(b"alice data")
    bob_doc = bob.upload(b"bob data")
    assert bob.download(bob_doc).status_code == 200          # legitimate
    # Bob swaps his document ID for Alice's in the URL / form
    assert bob.download(alice_doc).status_code == 404
    assert bob.post(f"/documents/{alice_doc}/delete").status_code == 404
    assert bob.share(alice_doc, "bob", "editor").status_code == 404
    # A random / non-existent ID gives the SAME answer -> no existence oracle
    r_fake = bob.download("00000000-0000-4000-8000-000000000000")
    assert r_fake.status_code == 404
    # Alice's document is untouched
    assert alice.download(alice_doc).data == b"alice data"


# ---------------------------------------------------------------------------
# Scenario 3 - Storage exposure
# ---------------------------------------------------------------------------
def test_s3_storage_exposure_reveals_no_content(app, make_user, db):
    alice = make_user("alice")
    secret = b"CONFIDENTIAL: merger with ACME on 1 Jan"
    doc = alice.upload(secret, "merger_plan.txt")
    # Attacker copies the whole blob directory and the whole database
    blobs = {p.name: p.read_bytes() for p in app.config["STORAGE_DIR"].iterdir()}
    dump = "\n".join(str(dict(r)) for t in ("users", "documents", "document_keys", "document_permissions")
                     for r in db.execute(f"SELECT * FROM {t}"))
    for data in blobs.values():
        assert secret not in data and b"merger" not in data
    assert "merger" not in dump and "CONFIDENTIAL" not in dump
    assert "Wonderland" not in dump                       # no password
    # Even with the wrapped key from the DB the attacker cannot decrypt without
    # alice's private key (which is encrypted with her password + server KEK).
    row = db.execute("SELECT wrapped_dek FROM document_keys WHERE document_id=?", (doc,)).fetchone()
    assert len(row["wrapped_dek"]) == 384                 # RSA-3072 ciphertext, opaque


# ---------------------------------------------------------------------------
# Scenario 4 - Document modification outside the application
# ---------------------------------------------------------------------------
def test_s4_tampered_blob_is_detected(app, make_user, db):
    alice = make_user("alice")
    doc = alice.upload(b"Pay supplier 1,000 PKR")
    blob_path = app.config["STORAGE_DIR"] / db.execute(
        "SELECT blob_name FROM documents WHERE id=?", (doc,)).fetchone()["blob_name"]
    data = bytearray(blob_path.read_bytes()); data[20] ^= 0xFF        # attacker flips bits on disk
    blob_path.write_bytes(bytes(data))

    r = alice.download(doc)
    assert r.status_code == 409 and b"INTEGRITY CHECK FAILED" in r.data
    r = alice.post(f"/documents/{doc}/verify")
    assert b"INTEGRITY FAILURE" in r.data
    assert db.execute("SELECT COUNT(*) c FROM audit_log WHERE action='document.integrity_failure'"
                      ).fetchone()["c"] >= 1


def test_s4b_blob_swap_between_documents_is_detected(app, make_user, db):
    """Attacker replaces doc A's blob with doc B's (both valid ciphertexts of the same owner)."""
    alice = make_user("alice")
    a, b = alice.upload(b"document A"), alice.upload(b"document B")
    pa = app.config["STORAGE_DIR"] / db.execute("SELECT blob_name FROM documents WHERE id=?", (a,)).fetchone()[0]
    pb = app.config["STORAGE_DIR"] / db.execute("SELECT blob_name FROM documents WHERE id=?", (b,)).fetchone()[0]
    pa.write_bytes(pb.read_bytes())
    assert alice.download(a).status_code == 409           # AAD binds blob to its doc id


def test_s4c_db_signature_forgery_detected(make_user, db):
    """Attacker with DB access changes signed_by to frame another user."""
    alice, bob = make_user("alice"), make_user("bob")
    doc = alice.upload(b"signed by alice")
    db.execute("UPDATE documents SET signed_by=? WHERE id=?", (user_id(db, "bob"), doc))
    assert alice.download(doc).status_code == 409


# ---------------------------------------------------------------------------
# Scenario 5 - Privilege misuse
# ---------------------------------------------------------------------------
def test_s5_privilege_misuse(make_user, db):
    alice, bob, charlie = make_user("alice"), make_user("bob"), make_user("charlie")
    doc = alice.upload(b"plan")
    alice.share(doc, "bob", "viewer"); alice.share(doc, "charlie", "editor")
    # Viewer tries to edit, share, delete
    assert bob.post(f"/documents/{doc}/update", {"file": (io.BytesIO(b"x"), "x")},
                    content_type="multipart/form-data").status_code == 403
    assert bob.share(doc, "mallory", "viewer").status_code == 403
    assert bob.post(f"/documents/{doc}/delete").status_code == 403
    # Editor tries owner-only actions
    assert charlie.post(f"/documents/{doc}/delete").status_code == 403
    assert charlie.post(f"/documents/{doc}/revoke", {"user_id": user_id(db, "bob")}).status_code == 403
    # Normal user tries admin pages directly (button hidden, but server checks)
    for url in ("/admin/users", "/admin/audit", "/admin/integrity"):
        assert bob.c.get(url).status_code == 403
    assert bob.post(f"/admin/users/{user_id(db, 'alice')}/role", {"role": "admin"}).status_code == 403
    assert db.execute("SELECT system_role FROM users WHERE username='bob'").fetchone()[0] == "user"


def test_s5b_admin_cannot_read_user_documents(make_user, db):
    """Least privilege: even the administrator has no access to document contents."""
    alice, admin = make_user("alice"), make_user("admin", role="admin")
    doc = alice.upload(b"not for admin")
    assert admin.download(doc).status_code == 404
    assert admin.c.get(f"/documents/{doc}").status_code == 404
    assert db.execute("SELECT COUNT(*) FROM document_keys WHERE user_id=?",
                      (user_id(db, "admin"),)).fetchone()[0] == 0     # no wrapped key for admin


# ---------------------------------------------------------------------------
# Scenario 6 - Permission revocation
# ---------------------------------------------------------------------------
def test_s6_revocation_blocks_access_and_rekeys(app, make_user, db):
    alice, bob = make_user("alice"), make_user("bob")
    doc = alice.upload(b"shared then revoked")
    alice.share(doc, "bob", "viewer")
    assert bob.download(doc).data == b"shared then revoked"
    # Simulate Bob having kept his wrapped key + the old blob (insider)
    old_blob = db.execute("SELECT blob_name FROM documents WHERE id=?", (doc,)).fetchone()[0]
    bob_wrapped_old = db.execute("SELECT wrapped_dek FROM document_keys WHERE document_id=? AND user_id=?",
                                 (doc, user_id(db, "bob"))).fetchone()[0]

    r = alice.post(f"/documents/{doc}/revoke", {"user_id": user_id(db, "bob")})
    assert r.status_code == 302
    assert bob.download(doc).status_code == 404                       # immediately blocked
    row = db.execute("SELECT blob_name, key_generation FROM documents WHERE id=?", (doc,)).fetchone()
    assert row["key_generation"] == 2 and row["blob_name"] != old_blob  # re-keyed
    assert not (app.config["STORAGE_DIR"] / old_blob).exists()
    # Old DEK (if Bob had cached it) cannot decrypt the NEW blob
    from app.security import keystore
    bob_keys = next(k for h, k in keystore._UNLOCKED.items()
                    if db.execute("SELECT user_id FROM sessions WHERE token_hash=?", (h,)).fetchone()[0]
                    == user_id(db, "bob"))
    old_dek = crypto.rsa_unwrap(bob_keys.enc_private, bob_wrapped_old)
    new_blob = (app.config["STORAGE_DIR"] / row["blob_name"]).read_bytes()
    try:
        crypto.aead_decrypt(old_dek, new_blob, f"securedms|doc:{doc}|v1".encode())
        assert False, "old key must not decrypt re-keyed document"
    except crypto.IntegrityError:
        pass
    assert alice.download(doc).data == b"shared then revoked"          # owner unaffected


# ---------------------------------------------------------------------------
# Scenario 7 - Audit tampering
# ---------------------------------------------------------------------------
def _verify(app, db):
    return audit.verify_chain(db, app.config["SERVER_SECRETS"]["audit_hmac"], app.config["AUDIT_ANCHOR_FILE"])


def test_s7a_sql_update_delete_blocked_by_triggers(make_user, db):
    make_user("alice")
    for sql in ("UPDATE audit_log SET outcome='success' WHERE seq=1", "DELETE FROM audit_log WHERE seq=1"):
        try:
            db.execute(sql)
            assert False, "trigger should block"
        except Exception as exc:
            assert "append-only" in str(exc)


def test_s7b_modification_detected_even_if_triggers_dropped(app, make_user, db):
    mallory = make_user("mallory")
    mallory.download("00000000-0000-4000-8000-000000000000")   # creates an access_denied record
    db.execute("DROP TRIGGER audit_log_no_update")             # attacker with raw DB access
    db.execute("UPDATE audit_log SET outcome='success', action='document.download' "
               "WHERE action='document.access_denied'")
    res = _verify(app, db)
    assert not res["ok"] and any("MODIFIED" in p for p in res["problems"])


def test_s7c_recomputed_chain_still_detected_by_hmac(app, make_user, db):
    make_user("mallory")
    db.execute("DROP TRIGGER audit_log_no_update")
    # Attacker edits record 2 and recomputes ALL hashes so the chain looks valid
    rows = [dict(r) for r in db.execute("SELECT * FROM audit_log ORDER BY seq")]
    rows[1]["details"] = json.dumps({"forged": True})
    prev = audit.GENESIS_HASH
    for r in rows:
        r["prev_hash"] = prev
        r["entry_hash"] = audit.compute_entry_hash(prev, r)
        db.execute("UPDATE audit_log SET details=?, prev_hash=?, entry_hash=? WHERE seq=?",
                   (r["details"], r["prev_hash"], r["entry_hash"], r["seq"]))
        prev = r["entry_hash"]
    res = _verify(app, db)
    assert not res["ok"] and any("HMAC invalid" in p for p in res["problems"])


def test_s7d_deletion_and_truncation_detected(app, make_user, db):
    alice = make_user("alice"); alice.upload(); alice.upload()
    db.execute("DROP TRIGGER audit_log_no_delete")
    n = db.execute("SELECT MAX(seq) FROM audit_log").fetchone()[0]
    db.execute("DELETE FROM audit_log WHERE seq=2")             # middle record removed
    res = _verify(app, db)
    assert not res["ok"] and any("Missing record" in p for p in res["problems"])
    db.execute("DELETE FROM audit_log WHERE seq=?", (n,))      # tail truncated
    res = _verify(app, db)
    assert any("TRUNCATED" in p for p in res["problems"])
