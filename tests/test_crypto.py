"""
tests/test_crypto.py
====================
Unit tests for the cryptographic building blocks (app/security/crypto.py).

These tests exercise the primitives directly, WITHOUT a Flask app, so they
run in milliseconds. They cover:

  * AES-GCM roundtrip, tamper detection, nonce randomness
  * scrypt password hashing, salting, verify, wrong password, tamper clamp
  * RSA-OAEP wrap/unwrap and unwrap failure on tampered ciphertext
  * Ed25519 sign/verify and signature forgery detection
  * Keystore bundle: password + recovery unlock, wrong password, KEK binding,
    user-ID AAD binding (a stolen bundle copied into another row must fail)
  * Audit record redaction of sensitive keys

Run:
    pytest -v tests/test_crypto.py
"""
import pytest

from app.security import crypto, keystore


# ===========================================================================
# AES-256-GCM
# ===========================================================================
def test_aes_gcm_roundtrip_and_tamper_detection():
    key = crypto.new_aes_key()
    aad = b"securedms|doc:abc|v1"
    plaintext = b"the quick brown fox jumps over the lazy dog"
    blob = crypto.aead_encrypt(key, plaintext, aad)

    # Roundtrip
    assert crypto.aead_decrypt(key, blob, aad) == plaintext

    # Flipping any byte of the ciphertext (after the 12-byte nonce) fails
    tampered = bytearray(blob)
    tampered[-1] ^= 0x01
    with pytest.raises(crypto.IntegrityError):
        crypto.aead_decrypt(key, bytes(tampered), aad)

    # Wrong AAD fails (this is what stops blob-swapping between documents)
    with pytest.raises(crypto.IntegrityError):
        crypto.aead_decrypt(key, blob, b"securedms|doc:OTHER|v1")

    # Truncated blob fails cleanly (no IndexError)
    with pytest.raises(crypto.IntegrityError):
        crypto.aead_decrypt(key, blob[:10], aad)


def test_nonce_is_random_each_time():
    """Two encryptions of the SAME plaintext under the SAME key must use
    different nonces (no catastrophic GCM nonce reuse)."""
    key = crypto.new_aes_key()
    aad = b"x"
    b1 = crypto.aead_encrypt(key, b"same plaintext", aad)
    b2 = crypto.aead_encrypt(key, b"same plaintext", aad)

    assert b1[:12] != b2[:12]           # nonces differ
    assert b1 != b2                     # ciphertexts differ
    # Both decrypt fine under the same key
    assert crypto.aead_decrypt(key, b1, aad) == b"same plaintext"
    assert crypto.aead_decrypt(key, b2, aad) == b"same plaintext"


# ===========================================================================
# scrypt password hashing
# ===========================================================================
def test_password_hash_is_salted_and_verifies():
    # The clamp in crypto.verify_password() uses a *policy* range. When this
    # test calls verify_password() directly (no Flask app), we must declare
    # the range the test is using. Production sets the same at app startup
    # via create_app() -> crypto.configure_scrypt_bounds().
    crypto.configure_scrypt_bounds(n_min=2 ** 12, n_max=2 ** 12)

    h1 = crypto.hash_password("CorrectHorse#1", 2 ** 12)
    h2 = crypto.hash_password("CorrectHorse#1", 2 ** 12)

    assert h1 != h2                              # unique salt -> different hash
    assert "CorrectHorse" not in h1              # never plaintext
    assert "scrypt$" in h1                       # format tag
    assert crypto.verify_password("CorrectHorse#1", h1)
    assert crypto.verify_password("CorrectHorse#1", h2)


def test_password_verify_rejects_wrong_password():
    crypto.configure_scrypt_bounds(n_min=2 ** 12, n_max=2 ** 12)
    stored = crypto.hash_password("CorrectHorse#1", 2 ** 12)

    assert not crypto.verify_password("wrong", stored)
    assert not crypto.verify_password("", stored)
    assert not crypto.verify_password("CorrectHorse#1 ", stored)  # trailing space


def test_password_verify_rejects_malformed_hashes():
    """verify_password must fail closed (return False, not crash) on
    anything that is not a well-formed scrypt$... string."""
    crypto.configure_scrypt_bounds(n_min=2 ** 12, n_max=2 ** 12)

    bad_inputs = [
        "",
        "not-a-hash",
        "scrypt$bad$parts",
        "bcrypt$4096$8$1$AAAA$BBBB",                # wrong algo tag
        "scrypt$4096$8$1$AAAA$BBBB",                # invalid b64
        "scrypt$abc$8$1$AAAA$BBBB",                 # non-int N
    ]
    for bad in bad_inputs:
        # Must not raise; must return False
        assert crypto.verify_password("anything", bad) is False, bad


def test_password_verify_rejects_out_of_range_params():
    """SECURITY (Scenario 3 / threat T10): an attacker with DB-write access
    might try to weaken the stored scrypt cost so the password becomes
    cheap to brute-force. verify_password must reject such a row."""
    crypto.configure_scrypt_bounds(n_min=2 ** 14, n_max=2 ** 18)

    # A well-formed hash written with n=2 (attacker-tampered)
    import base64
    salt = crypto.random_bytes(16)
    digest = crypto.hash_password("CorrectHorse#1", 2)  # hash under n=2
    # Reformat so the *stored* row claims n=2
    tampered = f"scrypt$2$8$1${base64.b64encode(salt).decode()}${digest.split('$')[-1]}"

    # Must be rejected — not accepted cheaply.
    assert crypto.verify_password("CorrectHorse#1", tampered) is False

    # Also reject a wildly-too-high N (DoS via expensive verify)
    import hashlib
    huge = f"scrypt${2 ** 20}$8$1${base64.b64encode(salt).decode()}${base64.b64encode(hashlib.sha256(b'x').digest()).decode()}"
    assert crypto.verify_password("anything", huge) is False


# ===========================================================================
# RSA-OAEP key wrapping
# ===========================================================================
def test_rsa_wrap_and_unwrap():
    priv = crypto.generate_rsa_keypair()
    pub_pem = crypto.public_pem(priv)
    dek = crypto.new_aes_key()               # 32 bytes, small enough for OAEP

    wrapped = crypto.rsa_wrap(pub_pem, dek)
    assert len(wrapped) == 384               # RSA-3072 ciphertext = 384 bytes
    assert crypto.rsa_unwrap(priv, wrapped) == dek


def test_rsa_unwrap_fails_on_tampered_ciphertext():
    priv = crypto.generate_rsa_keypair()
    pub_pem = crypto.public_pem(priv)
    dek = crypto.new_aes_key()
    wrapped = bytearray(crypto.rsa_wrap(pub_pem, dek))
    wrapped[10] ^= 0xFF                      # corrupt one byte
    with pytest.raises(crypto.IntegrityError):
        crypto.rsa_unwrap(priv, bytes(wrapped))


def test_rsa_unwrap_with_wrong_key_fails():
    priv_a = crypto.generate_rsa_keypair()
    priv_b = crypto.generate_rsa_keypair()
    wrapped = crypto.rsa_wrap(crypto.public_pem(priv_a), crypto.new_aes_key())
    with pytest.raises(crypto.IntegrityError):
        crypto.rsa_unwrap(priv_b, wrapped)   # Bob can't unwrap Alice's blob


# ===========================================================================
# Ed25519 signatures
# ===========================================================================
def test_ed25519_sign_and_verify():
    signing = crypto.generate_signing_keypair()
    pub_pem = crypto.public_pem(signing)
    msg = b"securedms|sig|doc123|v1|abcdef"

    sig = crypto.sign(signing, msg)
    assert len(sig) == 64                             # Ed25519 signature size
    assert crypto.verify_signature(pub_pem, sig, msg) is True


def test_ed25519_rejects_modified_message():
    signing = crypto.generate_signing_keypair()
    pub_pem = crypto.public_pem(signing)
    sig = crypto.sign(signing, b"original message")

    assert crypto.verify_signature(pub_pem, sig, b"original message") is True
    assert crypto.verify_signature(pub_pem, sig, b"modified message") is False


def test_ed25519_rejects_wrong_signer():
    alice = crypto.generate_signing_keypair()
    bob = crypto.generate_signing_keypair()
    msg = b"important"
    bob_sig = crypto.sign(bob, msg)
    # Alice's public key must NOT verify Bob's signature
    assert crypto.verify_signature(crypto.public_pem(alice), bob_sig, msg) is False


def test_ed25519_rejects_garbage_signature():
    signing = crypto.generate_signing_keypair()
    pub_pem = crypto.public_pem(signing)
    msg = b"x"
    bad_sig = b"\x00" * 64
    assert crypto.verify_signature(pub_pem, bad_sig, msg) is False


# ===========================================================================
# Keystore: password + recovery unlock, KEK binding, user-ID AAD binding
# ===========================================================================
_TEST_KEK = b"\x11" * 32            # deterministic for the test
_TEST_SCRYPT_N = 2 ** 12


def _make_user_keys(user_id: str, password: str = "Wonderland#2026"):
    """Create a user's key bundle. Returns (bundle_dict, unlocked_keys)."""
    crypto.configure_scrypt_bounds(n_min=2 ** 12, n_max=2 ** 12)
    return keystore.create_user_keys(user_id, password, _TEST_KEK, _TEST_SCRYPT_N)


def _row_from_bundle(user_id: str, bundle: dict) -> dict:
    """Build the row-shaped dict that keystore.unlock_*() expects."""
    return {
        "id": user_id,
        "key_salt": bundle["key_salt"],
        "private_keys_pw": bundle["private_keys_pw"],
        "private_keys_rec": bundle["private_keys_rec"],
    }


def test_keystore_password_unlock_roundtrip():
    uid = "user-alice"
    bundle = _make_user_keys(uid)
    row = _row_from_bundle(uid, bundle)

    unlocked = keystore.unlock_with_password(row, "Wonderland#2026",
                                             _TEST_KEK, _TEST_SCRYPT_N)
    assert unlocked.enc_private is not None
    assert unlocked.sign_private is not None
    # The public key derived from the unlocked private key matches the stored one
    assert crypto.public_pem(unlocked.enc_private) == bundle["enc_public_key"]


def test_keystore_recovery_code_unlock_roundtrip():
    uid = "user-alice"
    bundle = _make_user_keys(uid)
    row = _row_from_bundle(uid, bundle)

    unlocked = keystore.unlock_with_recovery_code(row, bundle["recovery_code"], _TEST_KEK)
    assert crypto.public_pem(unlocked.enc_private) == bundle["enc_public_key"]


def test_keystore_wrong_password_fails():
    uid = "user-alice"
    bundle = _make_user_keys(uid)
    row = _row_from_bundle(uid, bundle)

    with pytest.raises(crypto.IntegrityError):
        keystore.unlock_with_password(row, "WrongPassword#1", _TEST_KEK, _TEST_SCRYPT_N)


def test_keystore_wrong_recovery_code_fails():
    uid = "user-alice"
    bundle = _make_user_keys(uid)
    row = _row_from_bundle(uid, bundle)

    with pytest.raises(crypto.IntegrityError):
        keystore.unlock_with_recovery_code(row, "AAAA-BBBB-CCCC-DDDD", _TEST_KEK)


def test_keystore_wrong_server_kek_fails():
    """Layer 2 of the bundle: without the exact server KEK, decryption fails
    even if the user's password is correct. This is what makes a stolen DB
    alone useless."""
    uid = "user-alice"
    bundle = _make_user_keys(uid)
    row = _row_from_bundle(uid, bundle)

    with pytest.raises(crypto.IntegrityError):
        keystore.unlock_with_password(row, "Wonderland#2026",
                                      b"\x22" * 32, _TEST_SCRYPT_N)   # wrong KEK


def test_keystore_bundle_is_bound_to_user_id():
    """AAD binding: copying Alice's encrypted bundle into Bob's row must fail.
    This defends against a DB attacker who tries to substitute one user's
    private keys for another's."""
    alice_bundle = _make_user_keys("user-alice")
    bob_row = {
        "id": "user-bob",                                    # Bob's ID
        "key_salt": alice_bundle["key_salt"],
        "private_keys_pw": alice_bundle["private_keys_pw"],  # but Alice's bundle
        "private_keys_rec": alice_bundle["private_keys_rec"],
    }

    with pytest.raises(crypto.IntegrityError):
        keystore.unlock_with_password(bob_row, "Wonderland#2026",
                                      _TEST_KEK, _TEST_SCRYPT_N)


def test_keystore_recovery_code_is_shown_once_and_regenerated():
    """rewrap_keys must produce a fresh recovery code (old one stops working)."""
    uid = "user-alice"
    bundle = _make_user_keys(uid)
    row = _row_from_bundle(uid, bundle)

    old_code = bundle["recovery_code"]
    keys = keystore.unlock_with_password(row, "Wonderland#2026",
                                         _TEST_KEK, _TEST_SCRYPT_N)
    rewrapped = keystore.rewrap_keys(uid, keys, "NewPassword#2027",
                                     _TEST_KEK, _TEST_SCRYPT_N)

    assert rewrapped["recovery_code"] != old_code
    new_row = {
        "id": uid,
        "key_salt": rewrapped["key_salt"],
        "private_keys_pw": rewrapped["private_keys_pw"],
        "private_keys_rec": rewrapped["private_keys_rec"],
    }
    # New password works, old password does not
    keystore.unlock_with_password(new_row, "NewPassword#2027",
                                  _TEST_KEK, _TEST_SCRYPT_N)
    with pytest.raises(crypto.IntegrityError):
        keystore.unlock_with_password(new_row, "Wonderland#2026",
                                      _TEST_KEK, _TEST_SCRYPT_N)
    # New recovery code works, old one does not
    keystore.unlock_with_recovery_code(new_row, rewrapped["recovery_code"], _TEST_KEK)
    with pytest.raises(crypto.IntegrityError):
        keystore.unlock_with_recovery_code(new_row, old_code, _TEST_KEK)


# ===========================================================================
# Constants / helper invariants
# ===========================================================================
def test_new_aes_key_length():
    assert len(crypto.new_aes_key()) == 32


def test_sha256_and_hmac_are_deterministic():
    assert crypto.sha256_hex(b"abc") == crypto.sha256_hex(b"abc")
    assert crypto.sha256_hex(b"abc") != crypto.sha256_hex(b"abd")
    assert crypto.hmac_sha256_hex(b"k" * 32, b"abc") == crypto.hmac_sha256_hex(b"k" * 32, b"abc")
    assert crypto.hmac_sha256_hex(b"k" * 32, b"abc") != crypto.hmac_sha256_hex(b"j" * 32, b"abc")


def test_constant_time_equal():
    assert crypto.constant_time_equal("abc", "abc") is True
    assert crypto.constant_time_equal("abc", "abd") is False
    assert crypto.constant_time_equal(b"\x00\x01", b"\x00\x01") is True