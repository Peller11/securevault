"""
User data-access functions.

Every query here uses '?' placeholders -- user-supplied values (username,
email, etc.) are always passed as bound parameters, never concatenated
into the SQL string. This is what prevents SQL injection.
"""
import datetime as dt


def create_user(db, *, username: str, email: str, password_hash: str, role: str = "user"):
    cursor = db.execute(
        """
        INSERT INTO users (username, email, password_hash, role, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (username, email, password_hash, role, dt.datetime.now(dt.timezone.utc).isoformat()),
    )
    db.commit()
    return get_user_by_id(db, cursor.lastrowid)


def get_user_by_id(db, user_id: int):
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_user_by_username(db, username: str):
    return db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_user_by_email(db, email: str):
    return db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def update_failed_login(db, *, user_id: int, failed_count: int, locked_until):
    db.execute(
        "UPDATE users SET failed_login_count = ?, locked_until = ? WHERE id = ?",
        (failed_count, locked_until, user_id),
    )
    db.commit()


def set_role(db, *, user_id: int, role: str):
    db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    db.commit()


def count_users(db) -> int:
    row = db.execute("SELECT COUNT(*) AS c FROM users").fetchone()
    return row["c"]


def list_all_users(db):
    """All users, most recently created first. Used only by the admin
    security dashboard -- never exposes password_hash to templates
    (templates simply don't reference that column)."""
    return db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()


def set_mfa_secret(db, *, user_id: int, secret: str | None, enabled: bool):
    db.execute(
        "UPDATE users SET mfa_secret = ?, mfa_enabled = ? WHERE id = ?",
        (secret, 1 if enabled else 0, user_id),
    )
    db.commit()
