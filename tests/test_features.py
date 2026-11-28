"""
tests/test_features.py
Functional + defensive tests for the Part 2 capabilities:
identity/authentication, upload/retrieval/deletion, sharing, verification,
audit trail, sessions, CSRF and headers.
"""
import io
import json

from app.security import audit
from app.services.storage import BlobStore
from conftest import PASSWORDS, UserClient, user_id


# ------------------------------------------------------------ authentication
def test_login_wrong_password_generic_message(app, make_user):
    make_user("alice")
    u = UserClient(app, "alice")
    r1 = u.login("wrong-password!!")
    r2 = UserClient(app, "nobody").login("whatever-password")
    assert r1.status_code == r2.status_code == 401
    assert b"Invalid username or password." in r1.data and b"Invalid username or password." in r2.data


def test_account_lockout_after_5_failures(app, make_user):
    make_user("alice")
    u = UserClient(app, "alice")
    for _ in range(5):
        u.login("bad-password-123")
    r = u.login()        # correct password, but locked
    assert r.status_code == 401 and b"locked" in r.data


def test_session_cookie_flags_and_logout(app, make_user):
    u = UserClient(app, "alice"); u.register()
    r = u.login()
    cookie = r.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    assert u.c.get("/documents").status_code == 200
    u.post("/logout")
    assert u.c.get("/documents").status_code == 302      # redirected to login


def test_csrf_token_required(make_user):
    alice = make_user("alice")
    r = alice.c.post("/documents/upload", data={"file": (io.BytesIO(b"x"), "x.txt")},
                     content_type="multipart/form-data")          # no csrf_token
    assert r.status_code == 400 and b"CSRF" in r.data


def test_security_headers(make_user):
    alice = make_user("alice")
    h = alice.c.get("/documents").headers
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert h["X-Frame-Options"] == "DENY" and h["X-Content-Type-Options"] == "nosniff"
    assert h["Cache-Control"] == "no-store"


# ------------------------------------------------------------ documents
def test_upload_download_roundtrip_and_encryption_at_rest(app, make_user, db):
    alice = make_user("alice")
    doc = alice.upload(b"Quarterly numbers: 42", "q3_report.txt")
    r = alice.download(doc)
    assert r.status_code == 200 and r.data == b"Quarterly numbers: 42"
    assert "attachment" in r.headers["Content-Disposition"]
    row = db.execute("SELECT * FROM documents WHERE id=?", (doc,)).fetchone()
    blob = (app.config["STORAGE_DIR"] / row["blob_name"]).read_bytes()
    assert b"Quarterly" not in blob                     # content encrypted on disk
    assert b"q3_report" not in row["enc_metadata"]      # filename encrypted in DB
    assert doc not in row["blob_name"]                  # storage name unrelated to doc id


def test_editor_can_update_viewer_cannot(make_user):
    alice, bob, charlie = make_user("alice"), make_user("bob"), make_user("charlie")
    doc = alice.upload(b"v1")
    alice.share(doc, "bob", "viewer"); alice.share(doc, "charlie", "editor")
    r = charlie.post(f"/documents/{doc}/update", {"file": (io.BytesIO(b"v2 by charlie"), "f.txt")},
                     content_type="multipart/form-data")
    assert r.status_code == 302
    assert bob.download(doc).data == b"v2 by charlie"    # viewer sees new version
    r = bob.post(f"/documents/{doc}/update", {"file": (io.BytesIO(b"evil"), "f.txt")},
                 content_type="multipart/form-data")
    assert r.status_code == 403
    assert alice.download(doc).data == b"v2 by charlie"


def test_delete_is_crypto_shredding(app, make_user, db):
    alice = make_user("alice")
    doc = alice.upload(b"to be deleted")
    blob_name = db.execute("SELECT blob_name FROM documents WHERE id=?", (doc,)).fetchone()["blob_name"]
    assert alice.post(f"/documents/{doc}/delete").status_code == 302
    assert not (app.config["STORAGE_DIR"] / blob_name).exists()
    assert db.execute("SELECT COUNT(*) c FROM document_keys WHERE document_id=?", (doc,)).fetchone()["c"] == 0
    assert alice.download(doc).status_code == 404


def test_share_expiry_enforced(make_user, db):
    alice, bob = make_user("alice"), make_user("bob")
    doc = alice.upload(b"temporary")
    alice.share(doc, "bob", "viewer", expires_days="1")
    assert bob.download(doc).status_code == 200
    db.execute("UPDATE document_permissions SET expires_at='2000-01-01T00:00:00+00:00' WHERE user_id=?",
               (user_id(db, "bob"),))
    assert bob.download(doc).status_code == 404          # expired grant = no access


def test_password_change_keeps_documents_and_kills_other_sessions(app, make_user):
    alice = make_user("alice")
    doc = alice.upload(b"still mine")
    other_device = UserClient(app, "alice"); other_device.login()
    assert other_device.c.get("/documents").status_code == 200
    r = alice.post("/account", {"old_password": PASSWORDS["alice"], "new_password": "BrandNew#Pass2027"})
    assert r.status_code == 200
    assert other_device.c.get("/documents").status_code == 302      # other session killed
    fresh = UserClient(app, "alice"); fresh.login("BrandNew#Pass2027")
    assert fresh.download(doc).data == b"still mine"                 # keys re-wrapped, docs intact


def test_recovery_code_restores_access(app):
    u = UserClient(app, "alice"); u.register(); u.login()
    doc = u.upload(b"recover me")
    r = UserClient(app, "x").c.post("/recover", data={"username": "alice", "recovery_code": u.recovery_code,
                                                      "new_password": "Recovered#2027!"})
    assert r.status_code == 200
    v = UserClient(app, "alice"); v.login("Recovered#2027!")
    assert v.download(doc).data == b"recover me"


def test_admin_disable_user_ends_sessions(make_user, db):
    admin, bob = make_user("admin", role="admin"), make_user("bob")
    assert bob.c.get("/documents").status_code == 200
    admin.post(f"/admin/users/{user_id(db, 'bob')}/active", {"active": "0"})
    assert bob.c.get("/documents").status_code == 302
    assert bob.login().status_code == 401


def test_blob_store_rejects_path_traversal(tmp_path):
    store = BlobStore(tmp_path)
    for bad in ("../../etc/passwd", "a.bin", "..%2f.bin"):
        try:
            store.read(bad)
            assert False, "should have raised"
        except ValueError:
            pass


# ------------------------------------------------------------ audit trail
def test_audit_records_actions_without_secrets(make_user, db):
    alice = make_user("alice")
    doc = alice.upload(b"SECRET-CONTENT-XYZ", "confidential_name.txt")
    alice.download(doc)
    rows = db.execute("SELECT action, outcome, details FROM audit_log").fetchall()
    actions = {r["action"] for r in rows}
    assert {"user.register", "auth.login", "document.upload", "document.download"} <= actions
    everything = json.dumps([dict(r) for r in db.execute("SELECT * FROM audit_log")])
    for secret in (PASSWORDS["alice"], "SECRET-CONTENT-XYZ", "confidential_name"):
        assert secret not in everything                  # no passwords / content / filenames


def test_audit_chain_verifies_when_untouched(app, make_user, db):
    alice = make_user("alice"); alice.upload()
    res = audit.verify_chain(db, app.config["SERVER_SECRETS"]["audit_hmac"], app.config["AUDIT_ANCHOR_FILE"])
    assert res["ok"], res["problems"]
