"""
app/security/server_secrets.py
==============================
Loads (or creates on first run) the server-side secrets:

  secrets/server_kek.key   32 bytes  "Key Encryption Key". Adds a SECOND layer of
                                     encryption around every user's private-key
                                     bundle. A stolen database alone is therefore
                                     not enough to even start guessing passwords
                                     offline — the attacker also needs this file.
  secrets/audit_hmac.key   32 bytes  Key for HMAC-ing audit records. Without it an
                                     attacker cannot re-compute valid MACs after
                                     editing the audit log.

These files are created with permission 0600 (owner read/write only).

PRODUCTION NOTE (limitation, documented in the report):
    In a real deployment these keys would live in a KMS/HSM (e.g. AWS KMS,
    HashiCorp Vault) and never touch the application disk. A file is used
    here so the prototype runs anywhere without extra infrastructure.
"""
import os
from pathlib import Path

_KEY_FILES = {
    "server_kek": "server_kek.key",
    "audit_hmac": "audit_hmac.key",
}


def _load_or_create(path: Path) -> bytes:
    if path.exists():
        data = path.read_bytes()
        if len(data) != 32:
            raise RuntimeError(f"Secret file {path} is corrupted (expected 32 bytes)")
        return data
    path.parent.mkdir(parents=True, exist_ok=True)
    data = os.urandom(32)
    # O_EXCL: never overwrite an existing key by accident
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return data


def load_server_secrets(secrets_dir) -> dict:
    """Return {'server_kek': bytes, 'audit_hmac': bytes}."""
    secrets_dir = Path(secrets_dir)
    return {name: _load_or_create(secrets_dir / fname) for name, fname in _KEY_FILES.items()}
