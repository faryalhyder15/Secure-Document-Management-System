"""
scripts/inspect_storage.py
"ATTACKER VIEW" for Part 3 Scenario 3 (Storage exposure).

Pretends an attacker has stolen a copy of the blob storage folder and the
database file, and prints EVERYTHING they can see. Use it to explain what
can and cannot be learned.

    python scripts/inspect_storage.py                 # inspect the normal instance
    python scripts/inspect_storage.py --root <dir>    # inspect another instance folder
"""
import argparse
import sqlite3
import string
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def printable_ratio(data: bytes) -> float:
    ok = sum(1 for b in data if chr(b) in string.printable)
    return ok / max(len(data), 1)


def inspect(root: Path, out=print):
    blobs_dir = root / "storage" / "blobs"
    db_path = root / "instance" / "securedms.sqlite3"
    out("=" * 78)
    out("ATTACKER VIEW 1: contents of storage/blobs/ (stolen file storage)")
    out("=" * 78)
    for p in sorted(blobs_dir.glob("*.bin")):
        data = p.read_bytes()
        out(f"{p.name}  size={len(data):6d} B  printable={printable_ratio(data):4.0%}  "
            f"first bytes={data[:24].hex()}")
    out("-> Names are random. Bytes look like random noise (AES-256-GCM ciphertext).")
    out("-> LEARNABLE: number of documents, approximate sizes, write times (file mtime).")
    out("-> NOT LEARNABLE: content, file names, owners, who has access.\n")

    out("=" * 78)
    out("ATTACKER VIEW 2: database file (stolen instance/securedms.sqlite3)")
    out("=" * 78)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    for u in conn.execute("SELECT username, system_role, substr(password_hash,1,40) h, "
                          "length(private_keys_pw) l FROM users"):
        out(f"user={u['username']:8s} role={u['system_role']:5s} hash={u['h']}...  "
            f"encrypted_private_keys={u['l']} B")
    for d in conn.execute("SELECT id, owner_id, plaintext_size, length(enc_metadata) m FROM documents"):
        out(f"doc={d['id']} size={d['plaintext_size']} B enc_metadata={d['m']} B (file name is encrypted)")
    out("-> LEARNABLE: usernames, roles, who owns/shares which document ID, sizes, timestamps,")
    out("   audit history (metadata). Password HASHES (salted scrypt; cost N is part of the hash).")
    out("-> NOT LEARNABLE: passwords, document contents, document names, private keys.")
    out("-> To decrypt, the attacker would ALSO need secrets/server_kek.key (stored separately)")
    out("   AND would then have to brute-force each user's password through scrypt.")
    conn.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=ROOT)
    inspect(ap.parse_args().root)
