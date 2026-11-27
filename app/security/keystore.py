"""
app/security/keystore.py
========================
User key management (Part 1.2 Q3 & Q4: "How will the system manage the
cryptographic material?" / "What if credentials or keys are lost?").

Every user gets TWO key pairs at registration:
    * RSA-3072   -> encryption key pair. Document keys (DEKs) are wrapped with
                    the PUBLIC key; only the PRIVATE key can unwrap them.
    * Ed25519    -> signing key pair. Used to sign every version of a document
                    the user uploads (integrity + non-repudiation).

Public keys are stored in plain form in the `users` table.
Private keys are stored as an encrypted "bundle", protected in two layers:

        bundle (JSON with both private keys)
          |  layer 1: AES-256-GCM with key = scrypt(password, key_salt)
          |  layer 2: AES-256-GCM with the server KEK (secrets/server_kek.key)
          v
        users.private_keys_pw

A SECOND copy is protected with the user's one-time RECOVERY CODE instead of
the password (users.private_keys_rec). This is how a user who forgets the
password can get back in without losing every document.

Key lifecycle:
    generate (register) -> unlock (login, kept ONLY in RAM) -> re-wrap
    (password change / recovery) -> forget (logout / session timeout).

The unlocked private keys are held in an in-memory dictionary keyed by the
session. They are NEVER written to disk, logs or the database.
"""
import json
import threading
from dataclasses import dataclass

from . import crypto


@dataclass
class UnlockedKeys:
    """The user's private keys, decrypted, living only in server RAM."""
    enc_private: object   # RSA private key object
    sign_private: object  # Ed25519 private key object


# ----------------------------------------------------------------------------
# In-memory cache of unlocked keys:  session_token_hash -> UnlockedKeys
# Limitation (documented): single-process only; a server restart forces all
# users to log in again (which is actually a safe default).
# ----------------------------------------------------------------------------
_UNLOCKED: dict = {}
_LOCK = threading.Lock()


def remember_keys(session_key: str, keys: UnlockedKeys) -> None:
    with _LOCK:
        _UNLOCKED[session_key] = keys


def get_keys(session_key: str):
    with _LOCK:
        return _UNLOCKED.get(session_key)


def forget_keys(session_key: str) -> None:
    with _LOCK:
        _UNLOCKED.pop(session_key, None)


def forget_all() -> None:
    with _LOCK:
        _UNLOCKED.clear()


# ----------------------------------------------------------------------------
# Bundle encryption helpers
# ----------------------------------------------------------------------------
def _aad(user_id: str, purpose: str) -> bytes:
    # Binds the encrypted bundle to ONE user: copying Alice's bundle into
    # Bob's row makes decryption fail.
    return f"securedms|user-keys|{purpose}|{user_id}".encode()


def _serialize_bundle(keys: UnlockedKeys) -> bytes:
    return json.dumps({
        "enc_private": crypto.b64e(crypto.private_der(keys.enc_private)),
        "sign_private": crypto.b64e(crypto.private_der(keys.sign_private)),
    }).encode()


def _deserialize_bundle(raw: bytes) -> UnlockedKeys:
    data = json.loads(raw)
    return UnlockedKeys(
        enc_private=crypto.load_private_der(crypto.b64d(data["enc_private"])),
        sign_private=crypto.load_private_der(crypto.b64d(data["sign_private"])),
    )


def _seal(bundle: bytes, user_key: bytes, server_kek: bytes, user_id: str, purpose: str) -> bytes:
    inner = crypto.aead_encrypt(user_key, bundle, _aad(user_id, purpose))      # layer 1
    return crypto.aead_encrypt(server_kek, inner, _aad(user_id, purpose + "-kek"))  # layer 2


def _open(sealed: bytes, user_key: bytes, server_kek: bytes, user_id: str, purpose: str) -> bytes:
    inner = crypto.aead_decrypt(server_kek, sealed, _aad(user_id, purpose + "-kek"))
    return crypto.aead_decrypt(user_key, inner, _aad(user_id, purpose))


# ----------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------
def create_user_keys(user_id: str, password: str, server_kek: bytes, scrypt_n: int) -> dict:
    """Generate fresh key pairs for a new user.

    Returns the column values for the `users` table PLUS the plaintext
    `recovery_code` (shown to the user ONCE and never stored)."""
    keys = UnlockedKeys(enc_private=crypto.generate_rsa_keypair(),
                        sign_private=crypto.generate_signing_keypair())
    key_salt = crypto.random_bytes(16)
    recovery_code = crypto.new_recovery_code()
    bundle = _serialize_bundle(keys)

    pw_key = crypto.derive_key_from_password(password, key_salt, scrypt_n)
    rec_key = crypto.derive_key_from_recovery_code(recovery_code, key_salt)
    return {
        "enc_public_key": crypto.public_pem(keys.enc_private),
        "sign_public_key": crypto.public_pem(keys.sign_private),
        "key_salt": key_salt,
        "private_keys_pw": _seal(bundle, pw_key, server_kek, user_id, "pw"),
        "private_keys_rec": _seal(bundle, rec_key, server_kek, user_id, "rec"),
        "recovery_code": recovery_code,
        "unlocked": keys,
    }


def unlock_with_password(user_row, password: str, server_kek: bytes, scrypt_n: int) -> UnlockedKeys:
    pw_key = crypto.derive_key_from_password(password, user_row["key_salt"], scrypt_n)
    raw = _open(user_row["private_keys_pw"], pw_key, server_kek, user_row["id"], "pw")
    return _deserialize_bundle(raw)


def unlock_with_recovery_code(user_row, code: str, server_kek: bytes) -> UnlockedKeys:
    rec_key = crypto.derive_key_from_recovery_code(code, user_row["key_salt"])
    raw = _open(user_row["private_keys_rec"], rec_key, server_kek, user_row["id"], "rec")
    return _deserialize_bundle(raw)


def rewrap_keys(user_id: str, keys: UnlockedKeys, new_password: str, server_kek: bytes,
                scrypt_n: int) -> dict:
    """Re-encrypt the SAME private keys under a new password AND a new
    recovery code (fresh salt each time). Documents do not need
    re-encryption, because the document keys are wrapped with the user's
    PUBLIC key, which is unchanged."""
    key_salt = crypto.random_bytes(16)
    bundle = _serialize_bundle(keys)
    out = {
        "key_salt": key_salt,
        "private_keys_pw": _seal(bundle, crypto.derive_key_from_password(new_password, key_salt, scrypt_n),
                                 server_kek, user_id, "pw"),
    }
    # The recovery copy uses key_salt too, so it must be re-sealed whenever the salt changes.
    recovery_code = crypto.new_recovery_code()
    out["private_keys_rec"] = _seal(bundle, crypto.derive_key_from_recovery_code(recovery_code, key_salt),
                                    server_kek, user_id, "rec")
    out["recovery_code"] = recovery_code  # caller must show the NEW code to the user once
    return out
