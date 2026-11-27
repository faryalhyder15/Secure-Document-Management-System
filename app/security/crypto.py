"""
app/security/crypto.py
======================
Thin, well-named wrappers around the *pyca/cryptography* library.
(... header unchanged ...)
"""
import base64
import hashlib
import hmac
import os
import secrets

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class IntegrityError(Exception):
    """Raised when ciphertext/tag/signature verification fails (tampering)."""


# --------------------------------------------------------------------------
# Randomness
# --------------------------------------------------------------------------
def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def new_aes_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


# --------------------------------------------------------------------------
# Hashing helpers
# --------------------------------------------------------------------------
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_sha256_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def constant_time_equal(a, b) -> bool:
    if isinstance(a, str):
        a = a.encode()
    if isinstance(b, str):
        b = b.encode()
    return hmac.compare_digest(a, b)


# --------------------------------------------------------------------------
# Password hashing (authentication)  -- scrypt
#
# FIX (security review item #1): the *stored* scrypt parameters n, r, p are
# attacker-controllable if the DB is writable (Scenario 3 / threat-model T10).
# We refuse to verify a hash whose parameters are outside an accepted range,
# so a DB-write attacker cannot set n=2 and crack the password cheaply.
#
# The bounds are configured from app.config so that:
#   * production uses  SCRYPT_N=2^15  (bounds 2^14..2^18)
#   * tests use         SCRYPT_N=2^12  (bounds 2^12..2^12) so the suite is fast
# Call configure_scrypt_bounds() once at app startup (see __init__.py).
# --------------------------------------------------------------------------
_SCRYPT_R, _SCRYPT_P, _HASH_LEN = 8, 1, 32

# Default bounds are the *production* ones. They can be narrowed by the
# application config (e.g. TestConfig).
_SCRYPT_N_MIN, _SCRYPT_N_MAX = 2 ** 14, 2 ** 18
_SCRYPT_R_MIN, _SCRYPT_R_MAX = 1, 32
_SCRYPT_P_MIN, _SCRYPT_P_MAX = 1, 16


def configure_scrypt_bounds(n_min: int, n_max: int = None,
                            r_min: int = None, r_max: int = None,
                            p_min: int = None, p_max: int = None) -> None:
    """Called once at app startup with the *accepted* range for stored hashes.

    Production (Config) keeps the defaults 2^14..2^18.
    Tests (TestConfig with SCRYPT_N=2^12) narrow this to 2^12..2^12 so the
    test suite is fast — and *also* proves the clamp works for the actual
    production range.
    """
    global _SCRYPT_N_MIN, _SCRYPT_N_MAX, _SCRYPT_R_MIN, _SCRYPT_R_MAX, _SCRYPT_P_MIN, _SCRYPT_P_MAX
    _SCRYPT_N_MIN = int(n_min)
    _SCRYPT_N_MAX = int(n_max) if n_max is not None else int(n_min)
    if r_min is not None:
        _SCRYPT_R_MIN = int(r_min)
    if r_max is not None:
        _SCRYPT_R_MAX = int(r_max)
    if p_min is not None:
        _SCRYPT_P_MIN = int(p_min)
    if p_max is not None:
        _SCRYPT_P_MAX = int(p_max)


def _scrypt(password: str, salt: bytes, n: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=_SCRYPT_R,
                          p=_SCRYPT_P, dklen=_HASH_LEN, maxmem=128 * 1024 * 1024)


def hash_password(password: str, n: int) -> str:
    salt = random_bytes(16)
    digest = _scrypt(password, salt, n)
    b64 = lambda b: base64.b64encode(b).decode()
    return f"scrypt${n}${_SCRYPT_R}${_SCRYPT_P}${b64(salt)}${b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        n, r, p = int(n), int(r), int(p)
        # FIX: reject tampered / out-of-range parameters. Fail closed.
        if not (_SCRYPT_N_MIN <= n <= _SCRYPT_N_MAX
                and _SCRYPT_R_MIN <= r <= _SCRYPT_R_MAX
                and _SCRYPT_P_MIN <= p <= _SCRYPT_P_MAX):
            return False
        digest = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(salt_b64),
                                n=n, r=r, p=p, dklen=_HASH_LEN,
                                maxmem=128 * 1024 * 1024)
        return constant_time_equal(digest, base64.b64decode(hash_b64))
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------------
# Key derivation (for encrypting the user's private keys)
# --------------------------------------------------------------------------
def derive_key_from_password(password: str, salt: bytes, n: int) -> bytes:
    return _scrypt(password, salt, n)


def derive_key_from_recovery_code(code: str, salt: bytes) -> bytes:
    normalized = code.replace("-", "").strip().upper().encode()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=b"securedms-recovery-v1").derive(normalized)


def new_recovery_code() -> str:
    raw = base64.b32encode(secrets.token_bytes(16)).decode().rstrip("=")
    return "-".join(raw[i:i + 4] for i in range(0, len(raw), 4))


# --------------------------------------------------------------------------
# AEAD
# --------------------------------------------------------------------------
def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = random_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < 12 + 16:
        raise IntegrityError("ciphertext too short / truncated")
    try:
        return AESGCM(key).decrypt(blob[:12], blob[12:], aad)
    except InvalidTag as exc:
        raise IntegrityError("authentication tag mismatch - data was modified") from exc


# --------------------------------------------------------------------------
# Asymmetric
# --------------------------------------------------------------------------
def generate_rsa_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def rsa_wrap(public_key_pem: str, key_to_wrap: bytes) -> bytes:
    pub = serialization.load_pem_public_key(public_key_pem.encode())
    return pub.encrypt(key_to_wrap, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))


def rsa_unwrap(private_key, wrapped: bytes) -> bytes:
    try:
        return private_key.decrypt(wrapped, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    except ValueError as exc:
        raise IntegrityError("could not unwrap document key") from exc


def generate_signing_keypair():
    return ed25519.Ed25519PrivateKey.generate()


def sign(private_key, message: bytes) -> bytes:
    return private_key.sign(message)


def verify_signature(public_key_pem: str, signature: bytes, message: bytes) -> bool:
    try:
        serialization.load_pem_public_key(public_key_pem.encode()).verify(signature, message)
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------------------
# Serialisation helpers
# --------------------------------------------------------------------------
def public_pem(private_key) -> str:
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def private_der(private_key) -> bytes:
    return private_key.private_bytes(serialization.Encoding.DER,
                                     serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption())


def load_private_der(data: bytes):
    return serialization.load_der_private_key(data, password=None)


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(data: str) -> bytes:
    return base64.b64decode(data)