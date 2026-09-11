"""
Admin security dashboard.

By design, this blueprint exposes AGGREGATE and metadata-level views only:
login attempts, audit logs, user/file counts, and a simple "suspicious IP"
heuristic. There is intentionally NO route here (or anywhere else in the
application) that lets an admin decrypt or download another user's file
contents -- ownership checks in app/routes/files.py are absolute and are
not bypassed by role. If a future policy requires supervised access to a
user's files (e.g. a legal hold), that must be implemented as an explicit,
separately audited feature with its own consent/authorization trail --
not as an implicit admin privilege.
"""
from flask import Blueprint, render_template

from app.db import get_db
from app.models import user as user_model
from app.models import file as file_model
from app.models import login_attempt as login_attempt_model
from app.services import auth_service, audit_service

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

_BAR_CHART_WIDTH = 460


def _build_type_bar_chart(rows):
    if not rows:
        return []
    max_count = max(row["count"] for row in rows) or 1
    bars = []
    for row in rows:
        width = max(6, (row["count"] / max_count) * _BAR_CHART_WIDTH)
        bars.append({
            "label": row["mime_type"],
            "count": row["count"],
            "width": f"{width:.1f}",
        })
    return bars


@admin_bp.route("/")
@auth_service.admin_required
def index():
    db = get_db()

    stats = {
        "user_count": user_model.count_users(db),
        "file_count": file_model.count_files(db),
        "total_storage_bytes": file_model.total_storage_bytes(db),
    }

    # --- Users tab: enrich each user row with computed, display-only fields.
    # No password_hash or any secret ever leaves this function.
    file_stats_by_user = file_model.file_stats_by_user(db)
    users = []
    for row in user_model.list_all_users(db):
        file_stats = file_stats_by_user.get(row["id"])
        users.append({
            "id": row["id"],
            "username": row["username"],
            "email": row["email"],
            "role": row["role"],
            "is_locked": auth_service.is_account_locked(row),
            "failed_login_count": row["failed_login_count"],
            "file_count": file_stats["file_count"] if file_stats else 0,
            "storage_bytes": file_stats["total_bytes"] if file_stats else 0,
            "created_at": row["created_at"],
        })

    # File Statistics: aggregate metadata only, never file contents.
    file_type_breakdown = file_model.file_type_breakdown(db)

    return render_template(
        "admin.html",
        stats=stats,
        users=users,
        # Security Events: curated, security-relevant signal.
        security_events=audit_service.security_events(db, limit=50),
        suspicious_ips=login_attempt_model.suspicious_ips(db),
        failed_attempts=login_attempt_model.recent_failed_attempts(db, limit=30),
        # Login Attempts: the complete raw log, success and failure alike.
        recent_attempts=login_attempt_model.recent_attempts(db, limit=50),
        # File Statistics: aggregate metadata only, never file contents.
        file_type_breakdown=file_type_breakdown,
        file_type_bars=_build_type_bar_chart(file_type_breakdown),
        bar_chart_width=_BAR_CHART_WIDTH,
        largest_files=file_model.largest_files(db, limit=10),
        # System Activity: the full, unfiltered audit trail.
        audit_logs=audit_service.recent_logs(db, limit=50),
    )
