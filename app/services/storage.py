"""
app/services/storage.py
=======================
Encrypted blob store (Part 1.1: "How will uploaded documents be stored?").

* Stores ONLY ciphertext (AES-256-GCM output). Plaintext never touches disk.
* File names are 128-bit random hex strings, unrelated to the document ID,
  owner or original filename. Someone browsing storage/blobs/ learns nothing
  except the number of files and their approximate sizes.
* Kept in a separate directory from the database (storage separation). In
  production this would be object storage (e.g. S3 with its own IAM policy).
* Blob names are validated so a malicious value can never cause path
  traversal (e.g. "../../etc/passwd").
"""
import os
import re
import secrets
from pathlib import Path

_BLOB_NAME_RE = re.compile(r"^[0-9a-f]{32}\.bin$")


class BlobStore:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, blob_name: str) -> Path:
        if not _BLOB_NAME_RE.match(blob_name):
            raise ValueError("invalid blob name")  # path traversal guard
        return self.root / blob_name

    @staticmethod
    def new_blob_name() -> str:
        return secrets.token_hex(16) + ".bin"

    def write(self, blob_name: str, data: bytes) -> None:
        path = self._path(blob_name)
        tmp = path.with_suffix(".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)  # atomic: readers never see half a file

    def read(self, blob_name: str) -> bytes:
        return self._path(blob_name).read_bytes()

    def exists(self, blob_name: str) -> bool:
        return self._path(blob_name).exists()

    def delete(self, blob_name: str) -> None:
        """Overwrite with random bytes, then remove.

        LIMITATION (documented): on SSDs / copy-on-write file systems the
        overwrite is not guaranteed to hit the same physical blocks. Our real
        protection is crypto-shredding: once the wrapped document keys are
        deleted from the DB, any leftover ciphertext is undecryptable.
        """
        path = self._path(blob_name)
        if path.exists():
            size = path.stat().st_size
            with open(path, "r+b") as fh:
                fh.write(os.urandom(size))
                fh.flush()
                os.fsync(fh.fileno())
            path.unlink()
