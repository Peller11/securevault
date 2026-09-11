import datetime as dt


def create_file(db, *, user_id: int, stored_filename: str, original_filename: str,
                 mime_type: str, size_bytes: int, nonce_b64: str):
    cursor = db.execute(
        """
        INSERT INTO files (user_id, stored_filename, original_filename, mime_type, size_bytes, nonce_b64, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            stored_filename,
            original_filename,
            mime_type,
            size_bytes,
            nonce_b64,
            dt.datetime.now(dt.timezone.utc).isoformat(),
        ),
    )
    db.commit()
    return get_file_by_id(db, cursor.lastrowid)


def get_file_by_id(db, file_id: int):
    return db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()


def list_files_for_user(db, user_id: int):
    return db.execute(
        "SELECT * FROM files WHERE user_id = ? ORDER BY created_at DESC", (user_id,)
    ).fetchall()


def delete_file(db, file_id: int):
    db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    db.commit()


def count_files(db) -> int:
    row = db.execute("SELECT COUNT(*) AS c FROM files").fetchone()
    return row["c"]


def total_storage_bytes_for_user(db, user_id: int) -> int:
    row = db.execute(
        "SELECT COALESCE(SUM(size_bytes), 0) AS total FROM files WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    return row["total"]


def total_storage_bytes(db) -> int:
    row = db.execute("SELECT COALESCE(SUM(size_bytes), 0) AS total FROM files").fetchone()
    return row["total"]


def file_stats_by_user(db):
    """Per-user file count + storage used. Metadata only -- used by the
    admin Users tab; never touches file contents."""
    rows = db.execute(
        """
        SELECT user_id, COUNT(*) AS file_count, COALESCE(SUM(size_bytes), 0) AS total_bytes
        FROM files
        GROUP BY user_id
        """
    ).fetchall()
    return {row["user_id"]: row for row in rows}


def file_type_breakdown(db):
    """Count and total size per MIME type, for the admin File Statistics tab."""
    return db.execute(
        """
        SELECT mime_type, COUNT(*) AS count, COALESCE(SUM(size_bytes), 0) AS total_bytes
        FROM files
        GROUP BY mime_type
        ORDER BY count DESC
        """
    ).fetchall()


def largest_files(db, limit: int = 10):
    """Metadata only (name, owner, size, date) -- admins can see this to
    understand storage usage, but this query never touches encrypted
    contents and no route exposes a decrypt/download action for it."""
    return db.execute(
        """
        SELECT files.id, files.original_filename, files.size_bytes, files.mime_type,
               files.created_at, users.username
        FROM files
        JOIN users ON users.id = files.user_id
        ORDER BY files.size_bytes DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
