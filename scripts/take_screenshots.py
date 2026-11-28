"""
scripts/take_screenshots.py
===========================
Captures the demonstration screenshots in evidence/screenshots/ automatically
(manual Part 5 item 8: "demonstration screenshots").

    pip install playwright && playwright install chromium     # one time
    python scripts/take_screenshots.py

What it does:
  1. creates a throw-away data folder, seeds the demo accounts/documents
  2. starts the server on http://127.0.0.1:5055 in the background
  3. drives a headless browser through the normal workflow AND the attack
     scenarios, saving a PNG for each step
  4. stops the server and deletes the throw-away data
"""
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "evidence" / "screenshots"
BASE = "http://127.0.0.1:5055"
PW = {"admin": "Overseer#2026!", "alice": "Wonderland#2026", "bob": "Builder#2026xy",
      "charlie": "Chocolate#2026", "mallory": "Intruder#2026!"}


def wait_for_server():
    for _ in range(60):
        try:
            urllib.request.urlopen(BASE + "/login", timeout=1)
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("server did not start")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    data = Path(tempfile.mkdtemp(prefix="securedms_shots_"))
    env = dict(os.environ, SDMS_DATA_DIR=str(data))
    subprocess.run([sys.executable, str(ROOT / "scripts" / "seed_demo_data.py")], env=env, check=True)
    server = subprocess.Popen([sys.executable, str(ROOT / "run.py"), "--http", "--port", "5055"], env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    db = sqlite3.connect(str(data / "instance" / "securedms.sqlite3"), isolation_level=None)
    try:
        wait_for_server()
        doc = lambda name_part: None  # placeholder, replaced below
        with sync_playwright() as p:
            browser = p.chromium.launch()

            def session(user):
                ctx = browser.new_context(viewport={"width": 1280, "height": 860})
                page = ctx.new_page()
                page.goto(BASE + "/login")
                page.fill("input[name=username]", user)
                page.fill("input[name=password]", PW[user])
                page.click("button:has-text('Log in')")
                page.wait_for_load_state()
                return page

            def shot(page, name):
                page.screenshot(path=str(OUT / f"{name}.png"), full_page=True)
                print("saved", name)

            # ---------- normal workflow
            anon = browser.new_page(viewport={"width": 1280, "height": 760})
            anon.goto(BASE + "/login"); shot(anon, "01_login_page")
            anon.goto(BASE + "/register")
            anon.fill("input[name=username]", "newstudent")
            anon.fill("input[name=password]", "MyLongPassphrase#1")
            anon.click("button:has-text('Register')"); anon.wait_for_load_state()
            shot(anon, "02_registration_recovery_code")

            alice = session("alice"); shot(alice, "03_alice_dashboard")
            alice.click("text=project_plan.txt"); alice.wait_for_load_state()
            plan_url = alice.url
            plan_id = plan_url.rstrip("/").split("/")[-1]
            shot(alice, "04_document_detail_owner_acl")
            alice.click("button:has-text('Verify integrity')"); alice.wait_for_load_state()
            shot(alice, "05_integrity_verified_ok")
            alice.goto(BASE + "/documents/upload"); shot(alice, "06_upload_page")
            alice.goto(BASE + "/documents")
            alice.click("text=salary_sheet_FAKE.csv"); alice.wait_for_load_state()
            salary_url = alice.url
            salary_id = salary_url.rstrip("/").split("/")[-1]

            bob = session("bob"); shot(bob, "07_bob_dashboard_shared_with_me")
            bob.goto(plan_url); shot(bob, "08_bob_viewer_no_owner_controls")

            # ---------- S1 + S2: unauthorized access / identifier manipulation
            mallory = session("mallory")
            mallory.goto(salary_url); shot(mallory, "09_S1_S2_mallory_idor_denied_404")

            # ---------- S5: privilege misuse
            bob.goto(BASE + "/admin/audit"); shot(bob, "10_S5_bob_admin_page_forbidden_403")
            admin = session("admin")
            admin.goto(salary_url); shot(admin, "11_S5_admin_cannot_read_documents_404")

            # ---------- S4: tamper with blob on disk
            blob = db.execute("SELECT blob_name FROM documents WHERE id=?", (salary_id,)).fetchone()[0]
            bp = data / "storage" / "blobs" / blob
            raw = bytearray(bp.read_bytes()); raw[30] ^= 0xFF; bp.write_bytes(bytes(raw))
            alice.goto(salary_url + "/download"); shot(alice, "12_S4_tampered_download_blocked_409")
            alice.goto(salary_url)
            alice.click("button:has-text('Verify integrity')"); alice.wait_for_load_state()
            shot(alice, "13_S4_verify_shows_integrity_failure")
            admin.goto(BASE + "/admin/integrity")
            admin.click("button:has-text('Run scan')"); admin.wait_for_load_state()
            shot(admin, "14_S4_admin_integrity_scan_modified")

            # ---------- S6: revocation
            alice.goto(plan_url)
            alice.click("tr:has-text('bob') button:has-text('Revoke')"); alice.wait_for_load_state()
            shot(alice, "15_S6_alice_revoked_bob_rekeyed")
            bob.goto(plan_url); shot(bob, "16_S6_bob_after_revocation_404")

            # ---------- admin views
            admin.goto(BASE + "/admin/users"); shot(admin, "17_admin_user_management")
            admin.goto(BASE + "/admin/audit"); shot(admin, "18_admin_audit_log_suspicious_activity")
            admin.click("button:has-text('Verify audit-log integrity')"); admin.wait_for_load_state()
            shot(admin, "19_S7_audit_verify_intact")

            # ---------- S7: audit tampering (attacker with raw DB access)
            db.execute("DROP TRIGGER audit_log_no_update")
            db.execute("UPDATE audit_log SET outcome='success' WHERE actor_username='mallory' "
                       "AND outcome='denied'")
            admin.goto(BASE + "/admin/audit")
            admin.click("button:has-text('Verify audit-log integrity')"); admin.wait_for_load_state()
            shot(admin, "20_S7_audit_tampering_detected")
            browser.close()
    finally:
        db.close()
        server.terminate(); server.wait(timeout=10)
        shutil.rmtree(data, ignore_errors=True)
    print(f"Screenshots in {OUT}")


if __name__ == "__main__":
    main()
