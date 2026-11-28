"""
tests/conftest.py
Shared pytest fixtures. Every test gets a BRAND-NEW, ISOLATED instance in a
temporary folder (own DB, own blob storage, own secrets, own audit anchor),
so tests never touch real data and never affect each other.
"""
import io
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app                 # noqa: E402
from app.config import TestConfig          # noqa: E402
from app.db import connect                 # noqa: E402
from app.security import keystore          # noqa: E402

PASSWORDS = {"admin": "Overseer#2026!", "alice": "Wonderland#2026", "bob": "Builder#2026xy",
             "charlie": "Chocolate#2026", "mallory": "Intruder#2026!"}


@pytest.fixture
def app(tmp_path):
    keystore.forget_all()
    application = create_app(TestConfig, {
        "DATABASE_PATH": tmp_path / "instance" / "test.sqlite3",
        "STORAGE_DIR": tmp_path / "storage" / "blobs",
        "SECRETS_DIR": tmp_path / "secrets",
        "AUDIT_ANCHOR_FILE": tmp_path / "audit_anchor" / "head.json",
    })
    yield application
    keystore.forget_all()


@pytest.fixture
def db(app):
    """Direct database access = what an attacker with file access would have."""
    conn = connect(app.config["DATABASE_PATH"])
    yield conn
    conn.close()


class UserClient:
    """A browser-like client for one user, with convenience helpers."""

    def __init__(self, app, username):
        self.app, self.username = app, username
        self.c = app.test_client()
        self.recovery_code = None

    # ---------------- auth
    def register(self, password=None, expect=200):
        r = self.c.post("/register", data={"username": self.username,
                                           "password": password or PASSWORDS[self.username]})
        assert r.status_code == expect, r.data[:500]
        m = re.search(rb'<pre class="code big">([^<]+)</pre>', r.data)
        self.recovery_code = m.group(1).decode() if m else None
        return r

    def login(self, password=None):
        return self.c.post("/login", data={"username": self.username,
                                           "password": password or PASSWORDS[self.username]})

    def csrf(self):
        r = self.c.get("/documents")
        m = re.search(rb'name="csrf_token" value="([^"]+)"', r.data)
        return m.group(1).decode() if m else ""

    def post(self, url, data=None, **kw):
        data = dict(data or {})
        data.setdefault("csrf_token", self.csrf())
        return self.c.post(url, data=data, **kw)

    # ---------------- documents
    def upload(self, content=b"top secret content", name="secret.txt"):
        r = self.post("/documents/upload", {"file": (io.BytesIO(content), name)},
                      content_type="multipart/form-data")
        assert r.status_code == 302, r.data[:500]
        return r.headers["Location"].rstrip("/").split("/")[-1]

    def share(self, doc_id, username, role="viewer", expires_days=""):
        return self.post(f"/documents/{doc_id}/share",
                         {"username": username, "role": role, "expires_days": expires_days})

    def download(self, doc_id):
        return self.c.get(f"/documents/{doc_id}/download")


@pytest.fixture
def make_user(app, db):
    """make_user('alice') -> registered + logged-in UserClient."""
    def _make(name, role="user"):
        u = UserClient(app, name)
        u.register()
        if role == "admin":
            db.execute("UPDATE users SET system_role='admin' WHERE username=?", (name,))
        r = u.login()
        assert r.status_code == 302, r.data[:300]
        return u
    return _make


def user_id(db, username):
    return db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]
