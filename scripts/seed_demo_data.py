"""
scripts/seed_demo_data.py
Creates CONTROLLED TEST ACCOUNTS and DOCUMENTS for demonstrations (manual,
Part 3: "test its own application using controlled test accounts").
No real secrets: all passwords below are demo-only and published on purpose.

    python scripts/seed_demo_data.py          # adds demo data to the normal instance
    python scripts/seed_demo_data.py --reset  # DELETES instance/, storage/, secrets/, audit_anchor/ first

Accounts created:
    admin   / Overseer#2026!   (system admin - manages users & audit, cannot read docs)
    alice   / Wonderland#2026   (owner of the demo documents)
    bob     / Builder#2026xy    (alice shares with bob as VIEWER)
    charlie / Chocolate#2026 (alice shares with charlie as EDITOR)
    mallory / Intruder#2026! (the "attacker" - has no permissions)
"""
import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from flask import g                             # noqa: E402

from app import create_app                      # noqa: E402
from app.config import Config                   # noqa: E402
from app.db import connect                      # noqa: E402
from app.security import keystore               # noqa: E402
from app.services import documents, users       # noqa: E402

DEMO_USERS = [
    ("admin", "Overseer#2026!", "admin"),
    ("alice", "Wonderland#2026", "user"),
    ("bob", "Builder#2026xy", "user"),
    ("charlie", "Chocolate#2026", "user"),
    ("mallory", "Intruder#2026!", "user"),
]


def reset_instance():
    for p in (Config.DATABASE_PATH.parent, Config.STORAGE_DIR.parent, Config.SECRETS_DIR,
              Config.AUDIT_ANCHOR_FILE.parent):
        if p.exists():
            shutil.rmtree(p)
            print(f"removed {p}")


def seed(app):
    """Create demo users + documents inside `app`. Returns {username: (user_row, keys)}."""
    sessions = {}
    with app.test_request_context():
        conn = connect(app.config["DATABASE_PATH"])
        try:
            for name, pw, role in DEMO_USERS:
                if conn.execute("SELECT 1 FROM users WHERE username = ?", (name,)).fetchone():
                    print(f"user {name} already exists - skipping")
                else:
                    users.register(conn, name, pw, system_role=role)
                    print(f"created user {name:8s} password={pw:18s} role={role}")
                sessions[name] = users.authenticate(conn, name, pw)

            alice, akeys = sessions["alice"]
            g.user = alice   # so audit records show "alice" as the actor
            data_dir = ROOT / "test_data"
            created = {}
            if conn.execute("SELECT 1 FROM documents WHERE owner_id = ?", (alice["id"],)).fetchone():
                print("demo documents already exist - skipping (use --reset for a clean start)")
                return created
            for fname in ("project_plan.txt", "salary_sheet_FAKE.csv", "board_minutes.md"):
                doc_id = documents.upload(conn, alice, akeys, fname, "text/plain", (data_dir / fname).read_bytes())
                created[fname] = doc_id
                print(f"alice uploaded {fname:24s} -> {doc_id}")
            documents.share(conn, alice, akeys, created["project_plan.txt"], "bob", "viewer")
            documents.share(conn, alice, akeys, created["project_plan.txt"], "charlie", "editor")
            documents.share(conn, alice, akeys, created["board_minutes.md"], "bob", "viewer", expires_days=7)
            print("alice shared project_plan.txt with bob (viewer) and charlie (editor)")
            print("alice shared board_minutes.md with bob (viewer, expires in 7 days)")
        finally:
            conn.close()
    keystore.forget_all()
    return created


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reset", action="store_true", help="wipe all data first")
    args = ap.parse_args()
    if args.reset:
        reset_instance()
    seed(create_app())
    print("\nDone. Start the server with:  python run.py --http   (or HTTPS, see README)")


if __name__ == "__main__":
    main()
