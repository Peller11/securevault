"""
Offline administrative management script.

Usage:
    python scripts/manage.py promote <username>
    python scripts/manage.py demote <username>
    python scripts/manage.py list-users

There is deliberately no HTTP endpoint that lets a logged-in user grant
themselves (or anyone else) the admin role -- that would be a privilege
escalation vector. Promotions are an out-of-band, operator-only action.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from app.db import get_db
from app.models import user as user_model


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1]
    app = create_app()

    with app.app_context():
        db = get_db()

        if command == "list-users":
            for row in db.execute("SELECT id, username, email, role FROM users ORDER BY id").fetchall():
                print(f"{row['id']:>4}  {row['username']:<20} {row['email']:<30} {row['role']}")
            return

        if command in ("promote", "demote"):
            if len(sys.argv) != 3:
                print(f"Usage: python scripts/manage.py {command} <username>")
                sys.exit(1)
            username = sys.argv[2]
            user_row = user_model.get_user_by_username(db, username)
            if not user_row:
                print(f"No such user: {username}")
                sys.exit(1)
            new_role = "admin" if command == "promote" else "user"
            user_model.set_role(db, user_id=user_row["id"], role=new_role)
            print(f"{username} is now '{new_role}'.")
            return

        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
