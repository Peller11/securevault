"""
Audit logging.

Every security-relevant event is recorded via `log_action`. We log the
acting user (if any), the action name, the source IP, a UTC timestamp,
whether it succeeded, and an optional resource id (e.g. a file id).
Audit log writes use the same parameterized-query discipline as
everything else and are never built from raw user input via string
formatting.
"""
import datetime as dt

from app.db import get_db


ACTION_REGISTER = "register"
ACTION_LOGIN = "login"
ACTION_LOGOUT = "logout"
ACTION_UPLOAD = "file_upload"
ACTION_DOWNLOAD = "file_download"
ACTION_DELETE = "file_delete"
ACTION_UNAUTHORIZED = "unauthorized_access_attempt"
ACTION_MFA_ENABLED = "mfa_enabled"
ACTION_MFA_VERIFY = "mfa_verification"
ACTION_MFA_RECOVERY_USED = "mfa_recovery_code_used"
ACTION_MFA_RECOVERY_REGENERATED = "mfa_recovery_codes_regenerated"
ACTION_MFA_DISABLED = "mfa_disabled"


def log_action(*, user_id, action: str, ip_address: str, success: bool, resource_id=None, db=None):
    db = db or get_db()
    db.execute(
        """
        INSERT INTO audit_logs (user_id, action, ip_address, timestamp, success, resource_id)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            action,
            ip_address,
            dt.datetime.now(dt.timezone.utc).isoformat(),
            1 if success else 0,
            str(resource_id) if resource_id is not None else None,
        ),
    )
    db.commit()


def recent_logs(db, limit: int = 100):
    return db.execute(
        """
        SELECT audit_logs.*, users.username AS username
        FROM audit_logs
        LEFT JOIN users ON users.id = audit_logs.user_id
        ORDER BY audit_logs.timestamp DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def security_events(db, limit: int = 50):
    """A curated subset of the audit log for the admin Security Events
    view: login activity and unauthorized-access attempts, as opposed to
    the full raw feed (see recent_logs / System Activity)."""
    return db.execute(
        """
        SELECT audit_logs.*, users.username AS username
        FROM audit_logs
        LEFT JOIN users ON users.id = audit_logs.user_id
        WHERE audit_logs.action IN (?, ?)
        ORDER BY audit_logs.timestamp DESC
        LIMIT ?
        """,
        (ACTION_LOGIN, ACTION_UNAUTHORIZED, limit),
    ).fetchall()


def logs_for_user(db, user_id: int, limit: int = 20):
    return db.execute(
        """
        SELECT * FROM audit_logs
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (user_id, limit),
    ).fetchall()


def activity_by_day_for_user(db, user_id: int, days: int = 7):
    """Daily counts of upload/download/delete actions for one user, most
    recent `days` days. Used to draw the dashboard's File Activity chart
    from real audit data rather than an invented series."""
    rows = db.execute(
        """
        SELECT substr(timestamp, 1, 10) AS day, action, COUNT(*) AS c
        FROM audit_logs
        WHERE user_id = ?
          AND action IN (?, ?, ?)
          AND success = 1
          AND date(timestamp) >= date('now', ?)
        GROUP BY day, action
        """,
        (user_id, ACTION_UPLOAD, ACTION_DOWNLOAD, ACTION_DELETE, f"-{days - 1} days"),
    ).fetchall()

    counts_by_day = {}
    for row in rows:
        day = row["day"]
        counts_by_day.setdefault(day, {"upload": 0, "download": 0, "delete": 0})
        key = row["action"].replace("file_", "")
        counts_by_day[day][key] = row["c"]

    # Fill in every day in the window, even ones with zero activity, so the
    # chart has a consistent x-axis.
    today = dt.datetime.now(dt.timezone.utc).date()
    series = []
    for offset in range(days - 1, -1, -1):
        day = (today - dt.timedelta(days=offset)).isoformat()
        entry = counts_by_day.get(day, {"upload": 0, "download": 0, "delete": 0})
        series.append({"day": day, **entry})
    return series
