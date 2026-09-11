import datetime as dt


def record_attempt(db, *, username_attempted: str, ip_address: str, success: bool):
    db.execute(
        """
        INSERT INTO login_attempts (username_attempted, ip_address, timestamp, success)
        VALUES (?, ?, ?, ?)
        """,
        (
            username_attempted,
            ip_address,
            dt.datetime.now(dt.timezone.utc).isoformat(),
            1 if success else 0,
        ),
    )
    db.commit()


def count_attempts_since(db, *, ip_address: str, since_iso: str) -> int:
    row = db.execute(
        """
        SELECT COUNT(*) AS c FROM login_attempts
        WHERE ip_address = ? AND timestamp >= ?
        """,
        (ip_address, since_iso),
    ).fetchone()
    return row["c"]


def recent_attempts(db, limit: int = 50):
    return db.execute(
        "SELECT * FROM login_attempts ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()


def recent_failed_attempts(db, limit: int = 50):
    return db.execute(
        "SELECT * FROM login_attempts WHERE success = 0 ORDER BY timestamp DESC LIMIT ?",
        (limit,),
    ).fetchall()


def suspicious_ips(db, min_failures: int = 5, limit: int = 20):
    """IPs with an unusually high number of failed attempts -- a simple
    heuristic to surface likely brute-force / credential-stuffing sources
    on the admin security dashboard."""
    return db.execute(
        """
        SELECT ip_address, COUNT(*) AS failure_count, MAX(timestamp) AS last_seen
        FROM login_attempts
        WHERE success = 0
        GROUP BY ip_address
        HAVING failure_count >= ?
        ORDER BY failure_count DESC
        LIMIT ?
        """,
        (min_failures, limit),
    ).fetchall()
