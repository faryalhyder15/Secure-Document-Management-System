"""
scripts/generate_cert.py
Creates a self-signed TLS certificate for local HTTPS (certs/server.crt + certs/server.key).

    python scripts/generate_cert.py

Uses the `cryptography` library (EC P-256 key, valid 365 days, SAN = localhost/127.0.0.1).
For a real deployment use a certificate from a trusted CA (e.g. Let's Encrypt).
"""
import datetime
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

OUT = Path(__file__).resolve().parent.parent / "certs"


def main():
    OUT.mkdir(exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureDMS local dev")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                           critical=False)
            .sign(key, hashes.SHA256()))
    key_path = OUT / "server.key"
    fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    (OUT / "server.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Created {OUT/'server.crt'} and {key_path}")


if __name__ == "__main__":
    main()
