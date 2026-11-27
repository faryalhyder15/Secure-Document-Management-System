"""
scripts/attack_demos.py
=======================
NARRATED ADVERSARIAL DEMONSTRATION of all 7 Part-3 scenarios.

    python scripts/attack_demos.py

* Runs against a FRESH, THROW-AWAY instance in a temporary folder
  (controlled test accounts + fictional data only; never your real data).
* For every scenario prints: threat & asset, steps, expected behaviour,
  actual behaviour, evidence (HTTP status, audit records) and limitations.
* Saves the full transcript to evidence/attack_demo_output.txt
  -> paste/screenshot this into the report as evidence.
"""
import io
import json
import re
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import create_app                       # noqa: E402
from app.config import TestConfig                # noqa: E402
from app.security import audit, crypto, keystore  # noqa: E402
from scripts.inspect_storage import inspect      # noqa: E402

LINES = []
RESULTS = []


def say(text=""):
    print(text)
    LINES.append(text)


def header(n, title, threat, asset):
    say("\n" + "#" * 78)
    say(f"# SCENARIO {n}: {title}")
    say("#" * 78)
    say(f"THREAT : {threat}")
    say(f"ASSET  : {asset}")


def verdict(n, ok, expected, actual, limitation):
    say(f"EXPECTED   : {expected}")
    say(f"ACTUAL     : {actual}")
    say(f"RESULT     : {'PASS ✅' if ok else 'FAIL ❌'}")
    say(f"LIMITATION : {limitation}")
    RESULTS.append((n, ok))


class Client:
    """Browser-like test client for one user."""
    def __init__(self, app, name, pw):
        self.c, self.name, self.pw = app.test_client(), name, pw

    def register(self):
        return self.c.post("/register", data={"username": self.name, "password": self.pw})

    def login(self):
        return self.c.post("/login", data={"username": self.name, "password": self.pw})

    def csrf(self):
        m = re.search(rb'name="csrf_token" value="([^"]+)"', self.c.get("/documents").data)
        return m.group(1).decode() if m else ""

    def post(self, url, data=None, **kw):
        data = dict(data or {}); data.setdefault("csrf_token", self.csrf())
        return self.c.post(url, data=data, **kw)

    def upload(self, content, name):
        r = self.post("/documents/upload", {"file": (io.BytesIO(content), name)},
                      content_type="multipart/form-data")
        return r.headers["Location"].split("/")[-1]


def audit_rows(db, where, params=()):
    return db.execute(f"SELECT seq, actor_username, action, outcome, target_id, details FROM audit_log "
                      f"WHERE {where} ORDER BY seq", params).fetchall()


def show_audit(rows):
    for r in rows:
        say(f"   audit #{r['seq']:<3} user={r['actor_username']} action={r['action']} "
            f"outcome={r['outcome']} target={(r['target_id'] or '')[:8]} details={r['details']}")


def main():
    tmp = Path(tempfile.mkdtemp(prefix="securedms_demo_"))
    app = create_app(TestConfig, {
        "DATABASE_PATH": tmp / "instance" / "securedms.sqlite3",
        "STORAGE_DIR": tmp / "storage" / "blobs",
        "SECRETS_DIR": tmp / "secrets",
        "AUDIT_ANCHOR_FILE": tmp / "audit_anchor" / "head.json",
    })
    db = sqlite3.connect(str(app.config["DATABASE_PATH"]), isolation_level=None)
    db.row_factory = sqlite3.Row
    uid = lambda n: db.execute("SELECT id FROM users WHERE username=?", (n,)).fetchone()[0]

    say("SecureDMS - Adversarial demonstration (controlled test instance)")
    say(f"Instance folder: {tmp}")
    say("(Test KDF cost N=2^12 is used here for speed; the real server uses N=2^15.)")
    users = {"alice": "Wonderland#2026", "bob": "Builder#2026xy", "charlie": "Chocolate#2026",
             "mallory": "Intruder#2026!", "admin": "Overseer#2026!"}
    cl = {}
    for n, pw in users.items():
        cl[n] = Client(app, n, pw); cl[n].register()
    db.execute("UPDATE users SET system_role='admin' WHERE username='admin'")
    for n in users:
        cl[n].login()
    alice, bob, charlie, mallory, admin = (cl[n] for n in ("alice", "bob", "charlie", "mallory", "admin"))
    salary = (ROOT / "test_data" / "salary_sheet_FAKE.csv").read_bytes()
    doc_salary = alice.upload(salary, "salary_sheet_FAKE.csv")
    doc_plan = alice.upload((ROOT / "test_data" / "project_plan.txt").read_bytes(), "project_plan.txt")
    alice.post(f"/documents/{doc_plan}/share", {"username": "bob", "role": "viewer"})
    alice.post(f"/documents/{doc_plan}/share", {"username": "charlie", "role": "editor"})
    say(f"Setup: users {list(users)} created; alice uploaded salary_sheet_FAKE.csv ({doc_salary[:8]}...) and")
    say(f"       project_plan.txt ({doc_plan[:8]}...), shared plan with bob=viewer, charlie=editor.")

    # ------------------------------------------------------------------ S1
    header(1, "Unauthorized document access",
           "A logged-in user with NO permission tries to open/download a document.",
           "Confidentiality of alice's salary_sheet_FAKE.csv")
    mark = db.execute("SELECT MAX(seq) FROM audit_log").fetchone()[0]
    say("STEPS:")
    say(f" 1. mallory logs in (valid account, no grants)")
    r1 = mallory.c.get(f"/documents/{doc_salary}")
    say(f" 2. GET /documents/{doc_salary}            -> HTTP {r1.status_code}")
    r2 = mallory.c.get(f"/documents/{doc_salary}/download")
    say(f" 3. GET /documents/{doc_salary}/download   -> HTTP {r2.status_code}")
    leaked = salary[:20] in r1.data or salary[:20] in r2.data
    say(" EVIDENCE (audit log):"); show_audit(audit_rows(db, "seq > ? AND actor_username='mallory'", (mark,)))
    verdict(1, r1.status_code == 404 and r2.status_code == 404 and not leaked,
            "Request refused server-side; no content returned; attempt recorded in audit log.",
            f"HTTP {r1.status_code}/{r2.status_code} 'Document not found'; content leaked = {leaked}; 2 denied records.",
            "A determined insider can still probe many IDs; mitigated by random UUIDs, identical 404s and the "
            "'suspicious activity' alert (>=3 denials). Rate limiting per user would be a further improvement.")

    # ------------------------------------------------------------------ S2
    header(2, "Identifier manipulation (IDOR)",
           "bob changes the document ID in the URL from his own document to alice's.",
           "alice's documents (confidentiality + integrity)")
    bob_doc = bob.upload(b"bob's own notes", "bob_notes.txt")
    say("STEPS:")
    r_ok = bob.c.get(f"/documents/{bob_doc}/download")
    say(f" 1. bob downloads HIS document  /documents/{bob_doc}/download -> HTTP {r_ok.status_code}")
    r_bad = bob.c.get(f"/documents/{doc_salary}/download")
    say(f" 2. bob edits the ID to alice's /documents/{doc_salary}/download -> HTTP {r_bad.status_code}")
    r_del = bob.post(f"/documents/{doc_salary}/delete")
    say(f" 3. bob POSTs delete with alice's ID                               -> HTTP {r_del.status_code}")
    r_fake = bob.c.get("/documents/00000000-0000-4000-8000-000000000000/download")
    say(f" 4. bob tries a non-existent ID                                    -> HTTP {r_fake.status_code}")
    still = alice.c.get(f"/documents/{doc_salary}/download").status_code
    say(f" 5. alice can still download her document                          -> HTTP {still}")
    verdict(2, r_ok.status_code == 200 and r_bad.status_code == r_del.status_code == r_fake.status_code == 404
            and still == 200,
            "Server checks the permission for the requested ID on every request; existing-but-forbidden and "
            "non-existent IDs are indistinguishable.",
            f"Own doc 200; alice's doc 404; delete 404; fake ID 404; alice unaffected ({still}).",
            "None found for this vector. IDs are random UUIDv4 (122 bits), but security never relies on that.")

    # ------------------------------------------------------------------ S3
    header(3, "Storage exposure",
           "An attacker obtains a copy of the blob storage AND the database file.",
           "Document contents, file names, user passwords and keys")
    say("STEPS: attacker lists and reads every stored file and dumps the DB:")
    inspect(tmp, out=say)
    all_blobs = b"".join(p.read_bytes() for p in app.config["STORAGE_DIR"].iterdir())
    found = [w for w in (b"Test User A", b"salary", b"Campus Library", b"project_plan") if w in all_blobs]
    dbdump = (tmp / "instance" / "securedms.sqlite3").read_bytes()
    found_db = [w for w in (b"Test User A", b"salary_sheet", b"Wonderland#2026") if w in dbdump]
    say(f" Search for known plaintext in blobs: {found or 'nothing found'}; in DB file: {found_db or 'nothing found'}")
    verdict(3, not found and not found_db,
            "Only ciphertext and non-sensitive metadata are exposed.",
            "No plaintext, no file names, no passwords present in stolen storage or DB.",
            "Metadata IS visible: usernames, number/size of documents, sharing graph, timestamps. "
            "If the attacker ALSO steals secrets/server_kek.key they can run an offline scrypt "
            "brute-force against weak passwords -> keep the KEK in a KMS/HSM and enforce strong passwords.")

    # ------------------------------------------------------------------ S4
    header(4, "Document modification outside the application",
           "Someone with file-system access edits the stored (encrypted) document directly.",
           "Integrity of alice's salary_sheet_FAKE.csv")
    blob_name = db.execute("SELECT blob_name FROM documents WHERE id=?", (doc_salary,)).fetchone()[0]
    p = app.config["STORAGE_DIR"] / blob_name
    original = p.read_bytes()
    data = bytearray(original); data[40] ^= 0x5A
    p.write_bytes(bytes(data))
    say(f"STEPS: 1. attacker flips bits at byte 40 of storage/blobs/{blob_name}")
    r = alice.c.get(f"/documents/{doc_salary}/download")
    say(f"       2. alice downloads -> HTTP {r.status_code}: "
        f"{(re.findall(r'<p>([^<]+)</p>', r.data.decode()) or [''])[0][:110]}")
    rv = alice.post(f"/documents/{doc_salary}/verify")
    say(f"       3. alice clicks 'Verify integrity' -> page says: "
        f"{'INTEGRITY FAILURE' if b'INTEGRITY FAILURE' in rv.data else 'intact'}")
    ra = admin.post("/admin/integrity")
    say(f"       4. admin runs storage integrity scan -> status MODIFIED shown: {b'MODIFIED' in ra.data}")
    say(" EVIDENCE (audit log):"); show_audit(audit_rows(db, "action IN ('document.integrity_failure','admin.integrity_scan')"))
    p.write_bytes(original)
    say("       5. (blob restored from backup) -> download now HTTP "
        f"{alice.c.get(f'/documents/{doc_salary}/download').status_code}")
    verdict(4, r.status_code == 409 and b"INTEGRITY FAILURE" in rv.data and b"MODIFIED" in ra.data,
            "Modification detected (AES-GCM tag + SHA-256 + Ed25519 signature); download blocked; logged.",
            "Download refused (409), verify page shows failure, admin scan flags MODIFIED, audit has records.",
            "Detection, not prevention: the document is unavailable until restored from backup. "
            "Mitigation: versioned/immutable object storage with backups.")

    # ------------------------------------------------------------------ S5
    header(5, "Privilege misuse",
           "Users attempt operations beyond their role (viewer edits/shares/deletes, editor revokes, "
           "user calls admin endpoints directly, admin tries to read documents).",
           "Document integrity, ACLs, administrative functions, confidentiality vs admin")
    steps = [
        ("bob (viewer) uploads new version", bob.post(f"/documents/{doc_plan}/update",
                                                      {"file": (io.BytesIO(b"hacked"), "x.txt")},
                                                      content_type="multipart/form-data").status_code, 403),
        ("bob (viewer) shares with mallory", bob.post(f"/documents/{doc_plan}/share",
                                                      {"username": "mallory", "role": "editor"}).status_code, 403),
        ("bob (viewer) deletes", bob.post(f"/documents/{doc_plan}/delete").status_code, 403),
        ("charlie (editor) revokes bob", charlie.post(f"/documents/{doc_plan}/revoke",
                                                      {"user_id": uid("bob")}).status_code, 403),
        ("charlie (editor) deletes", charlie.post(f"/documents/{doc_plan}/delete").status_code, 403),
        ("bob opens /admin/audit directly", bob.c.get("/admin/audit").status_code, 403),
        ("bob makes himself admin via POST", bob.post(f"/admin/users/{uid('bob')}/role",
                                                      {"role": "admin"}).status_code, 403),
        ("admin downloads alice's document", admin.c.get(f"/documents/{doc_salary}/download").status_code, 404),
    ]
    say("STEPS:")
    for text, got, exp in steps:
        say(f"   - {text:38s} -> HTTP {got} (expected {exp})")
    role_now = db.execute("SELECT system_role FROM users WHERE username='bob'").fetchone()[0]
    say(f"   bob's system_role afterwards: {role_now}")
    admin_keys = db.execute("SELECT COUNT(*) FROM document_keys WHERE user_id=?", (uid("admin"),)).fetchone()[0]
    say(f"   wrapped document keys owned by admin: {admin_keys}  (admin is cryptographically unable to decrypt)")
    verdict(5, all(g == e for _, g, e in steps) and role_now == "user" and admin_keys == 0,
            "Every operation outside the role is refused by the server and logged.",
            "All 8 attempts refused; no privilege change; admin has zero document keys.",
            "A malicious admin can still disable accounts or change roles (availability). Mitigation: "
            "two-person approval for admin actions; all admin actions are already audited.")

    # ------------------------------------------------------------------ S6
    header(6, "Permission revocation",
           "bob tries to access the shared document after alice revoked his permission.",
           "Confidentiality of project_plan.txt after revocation")
    say("STEPS:")
    before = bob.c.get(f"/documents/{doc_plan}/download")
    say(f" 1. bob downloads while still authorised -> HTTP {before.status_code} ({len(before.data)} bytes kept locally)")
    gen_before = db.execute("SELECT key_generation, blob_name FROM documents WHERE id=?", (doc_plan,)).fetchone()
    r = alice.post(f"/documents/{doc_plan}/revoke", {"user_id": uid("bob")})
    gen_after = db.execute("SELECT key_generation, blob_name FROM documents WHERE id=?", (doc_plan,)).fetchone()
    say(f" 2. alice revokes bob -> HTTP {r.status_code}; key generation {gen_before[0]} -> {gen_after[0]}, "
        f"blob {gen_before[1][:8]}.. -> {gen_after[1][:8]}.. (re-encrypted with NEW key)")
    after = bob.c.get(f"/documents/{doc_plan}/download")
    say(f" 3. bob downloads again -> HTTP {after.status_code}")
    still_listed = b"project_plan" in bob.c.get("/documents").data
    say(f" 4. document still in bob's dashboard: {still_listed}")
    ch = charlie.c.get(f"/documents/{doc_plan}/download").status_code
    say(f" 5. charlie (not revoked) still has access -> HTTP {ch}")
    say(" EVIDENCE (audit log):")
    show_audit(audit_rows(db, "action='document.revoke' OR (actor_username='bob' AND "
                              "action='document.access_denied' AND target_id=? AND details LIKE '%no permission%')",
                          (doc_plan,)))
    verdict(6, before.status_code == 200 and after.status_code == 404 and not still_listed and ch == 200
            and gen_after[0] == gen_before[0] + 1,
            "Access refused immediately; document re-keyed so any cached old key is useless; others unaffected.",
            f"Before 200 -> after {after.status_code}; re-keyed; charlie still {ch}.",
            "Copies bob ALREADY downloaded cannot be recalled (no system can 'un-send' data). Mitigations: "
            "least-privilege sharing (viewer, expiry dates), watermarking, or view-only DRM-style viewers.")

    # ------------------------------------------------------------------ S7
    header(7, "Audit tampering",
           "An insider with database access tries to alter or remove audit records to hide activity.",
           "Integrity & completeness of the audit trail")
    key, anchor = app.config["SERVER_SECRETS"]["audit_hmac"], app.config["AUDIT_ANCHOR_FILE"]
    vchk = lambda: audit.verify_chain(db, key, anchor)
    say(f"STEPS:\n 0. baseline verification -> ok={vchk()['ok']} ({vchk()['checked']} records)")
    try:
        db.execute("DELETE FROM audit_log WHERE actor_username='mallory'")
        say(" 1. DELETE mallory's records via SQL -> succeeded (BAD)")
        layer1 = False
    except sqlite3.DatabaseError as exc:
        say(f" 1. DELETE mallory's records via SQL -> BLOCKED: {exc}")
        layer1 = True
    db.execute("DROP TRIGGER audit_log_no_update"); db.execute("DROP TRIGGER audit_log_no_delete")
    say(" 2. attacker drops the protective triggers (raw DB file access)")
    db.execute("UPDATE audit_log SET outcome='success', action='document.download' "
               "WHERE actor_username='mallory' AND action='document.access_denied'")
    res_a = vchk()
    say(f" 3. rewrites mallory's 'access_denied' records as successes -> verify ok={res_a['ok']}")
    for p in res_a["problems"][:3]:
        say(f"      ! {p}")
    # attacker recomputes the chain
    rows = [dict(r) for r in db.execute("SELECT * FROM audit_log ORDER BY seq")]
    prev = audit.GENESIS_HASH
    for row in rows:
        row["prev_hash"] = prev; row["entry_hash"] = audit.compute_entry_hash(prev, row)
        db.execute("UPDATE audit_log SET prev_hash=?, entry_hash=? WHERE seq=?",
                   (row["prev_hash"], row["entry_hash"], row["seq"]))
        prev = row["entry_hash"]
    res_b = vchk()
    say(f" 4. recomputes every SHA-256 so the chain links again -> verify ok={res_b['ok']}")
    for p in res_b["problems"][:2]:
        say(f"      ! {p}")
    n = db.execute("SELECT MAX(seq) FROM audit_log").fetchone()[0]
    db.execute("DELETE FROM audit_log WHERE seq > ?", (n - 3,))
    res_c = vchk()
    say(f" 5. deletes the last 3 records (truncation) -> verify ok={res_c['ok']}")
    for p in [p for p in res_c["problems"] if "TRUNCATED" in p]:
        say(f"      ! {p}")
    verdict(7, layer1 and not res_a["ok"] and not res_b["ok"]
            and any("TRUNCATED" in p for p in res_c["problems"]),
            "SQL tampering blocked; any change, re-hashing or deletion detected by verification.",
            "Triggers blocked SQL DELETE; modification, recomputed chain (HMAC) and truncation (anchor) all detected.",
            "Detection, not prevention: someone with the DB AND the audit key AND the anchor file could rewrite "
            "history. Mitigation: ship logs in real time to a separate write-once (WORM) store / SIEM that the "
            "application server cannot modify.")

    # ------------------------------------------------------------------ summary
    say("\n" + "=" * 78)
    say("SUMMARY")
    for n, ok in RESULTS:
        say(f"  Scenario {n}: {'PASS' if ok else 'FAIL'}")
    out = ROOT / "evidence" / "attack_demo_output.txt"
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(LINES), encoding="utf-8")
    print(f"\nTranscript saved to {out}")
    keystore.forget_all()
    db.close()
    return all(ok for _, ok in RESULTS)


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
