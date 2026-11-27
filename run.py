"""
run.py — start the SecureDMS web server.

Usage:
    python run.py                 # HTTPS on https://127.0.0.1:5000 (needs certs, see below)
    python run.py --http          # plain HTTP (local testing only!)
    python run.py --port 8443

HTTPS: create a self-signed certificate first with
    python scripts/generate_cert.py
Your browser will warn that the certificate is self-signed — that is expected
for a local prototype (click "Advanced -> Proceed").

Why HTTPS matters: passwords and decrypted documents travel between browser
and server; TLS protects them in transit (confidentiality + integrity).
"""
import argparse
import os
from pathlib import Path

BASE = Path(__file__).resolve().parent
CERT, KEY = BASE / "certs" / "server.crt", BASE / "certs" / "server.key"


def main():
    parser = argparse.ArgumentParser(description="Run SecureDMS")
    parser.add_argument("--http", action="store_true", help="run without TLS (local testing only)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    use_tls = not args.http
    if use_tls and not (CERT.exists() and KEY.exists()):
        raise SystemExit("No TLS certificate found. Run:  python scripts/generate_cert.py\n"
                         "or start in plain HTTP for local testing:  python run.py --http")
    # Secure cookie flag must match the transport
    os.environ["SDMS_COOKIE_SECURE"] = "1" if use_tls else "0"

    from app import create_app   # import AFTER env var is set (config reads it)
    app = create_app()
    if not use_tls:
        print("WARNING: running over plain HTTP. Use only on your own machine for testing.")
    app.run(host=args.host, port=args.port, debug=False,   # debug=False: never expose the debugger
            ssl_context=(str(CERT), str(KEY)) if use_tls else None, threaded=True)


if __name__ == "__main__":
    main()
