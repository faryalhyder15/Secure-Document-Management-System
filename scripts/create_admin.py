"""
scripts/create_admin.py
Creates an administrator account from the command line (there is deliberately
NO way to become admin through the web registration form).

    python scripts/create_admin.py <username>

The password is typed interactively (not visible, not stored in shell history).
"""
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app          # noqa: E402
from app.db import connect          # noqa: E402
from app.services import users      # noqa: E402


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: python scripts/create_admin.py <username>")
    username = sys.argv[1]
    password = getpass.getpass("Admin password (min 10 chars): ")
    if password != getpass.getpass("Repeat password: "):
        raise SystemExit("Passwords do not match.")
    app = create_app()
    with app.test_request_context():
        conn = connect(app.config["DATABASE_PATH"])
        try:
            _uid, code = users.register(conn, username, password, system_role="admin")
        except users.UserError as exc:
            raise SystemExit(f"Error: {exc}")
        finally:
            conn.close()
    print(f"Admin '{username}' created.\nRECOVERY CODE (store it offline, shown once): {code}")


if __name__ == "__main__":
    main()
