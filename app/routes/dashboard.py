from flask import Blueprint, render_template

from app.db import get_db
from app.models import file as file_model
from app.services import auth_service, audit_service

dashboard_bp = Blueprint("dashboard", __name__)

# These reflect controls that are structurally always active for every
# request in this codebase (see app/__init__.py's security hooks and
# app/services/*), not per-request toggles -- so it's accurate to show
# them as a fixed status list rather than something that needs to be
# "checked" at render time.
SYSTEM_SECURITY_CONTROLS = [
    {"name": "Encryption", "detail": "AES-256-GCM at rest", "status": "ACTIVE"},
    {"name": "Authentication", "detail": "Argon2id password hashing", "status": "PROTECTED"},
    {"name": "CSRF Protection", "detail": "Per-session synchronizer token", "status": "ACTIVE"},
    {"name": "Rate Limiting", "detail": "Per-IP + per-account lockout", "status": "ACTIVE"},
    {"name": "Access Control", "detail": "Ownership check on every file op", "status": "ACTIVE"},
    {"name": "Audit Logging", "detail": "Every sensitive action recorded", "status": "ACTIVE"},
]

_CHART_WIDTH = 560
_CHART_HEIGHT = 150
_CHART_PAD_X = 10
_CHART_PAD_TOP = 12
_CHART_PAD_BOTTOM = 24


def _build_activity_chart(series: list[dict]) -> dict:
    """Turn real per-day upload/download/delete counts into SVG polyline
    point strings. Pure presentation math -- no data is invented here,
    only laid out on a canvas."""
    n = len(series)
    max_value = max([1] + [max(day["upload"], day["download"], day["delete"]) for day in series])
    plot_w = _CHART_WIDTH - 2 * _CHART_PAD_X
    plot_h = _CHART_HEIGHT - _CHART_PAD_TOP - _CHART_PAD_BOTTOM
    step = plot_w / (n - 1) if n > 1 else 0

    def points_for(key):
        pts = []
        for i, day in enumerate(series):
            x = _CHART_PAD_X + i * step
            value = day[key]
            y = _CHART_PAD_TOP + plot_h - (value / max_value) * plot_h
            pts.append(f"{x:.1f},{y:.1f}")
        return " ".join(pts)

    labels = []
    for i, day in enumerate(series):
        x = _CHART_PAD_X + i * step
        # "Mon", "Tue", etc. from the ISO date string, no extra deps.
        import datetime as _dt
        weekday = _dt.date.fromisoformat(day["day"]).strftime("%a")
        labels.append({"x": f"{x:.1f}", "text": weekday})

    return {
        "width": _CHART_WIDTH,
        "height": _CHART_HEIGHT,
        "upload_points": points_for("upload"),
        "download_points": points_for("download"),
        "delete_points": points_for("delete"),
        "labels": labels,
        "baseline_y": _CHART_HEIGHT - _CHART_PAD_BOTTOM,
        "has_activity": max_value > 1 or any(
            day["upload"] or day["download"] or day["delete"] for day in series
        ),
    }


@dashboard_bp.route("/")
@auth_service.login_required
def index():
    user = auth_service.current_user()
    db = get_db()

    files = file_model.list_files_for_user(db, user["id"])
    total_bytes = file_model.total_storage_bytes_for_user(db, user["id"])
    recent_activity = audit_service.logs_for_user(db, user["id"], limit=8)
    activity_series = audit_service.activity_by_day_for_user(db, user["id"], days=7)
    security = auth_service.compute_account_security_score(user)
    chart = _build_activity_chart(activity_series)

    return render_template(
        "dashboard.html",
        user=user,
        files=files[:6],
        file_count=len(files),
        total_bytes=total_bytes,
        recent_activity=recent_activity,
        chart=chart,
        security=security,
        gauge=_gauge_geometry(security["score"]),
        system_security=SYSTEM_SECURITY_CONTROLS,
    )


def _gauge_geometry(score: int) -> dict:
    import math
    radius = 42
    circumference = 2 * math.pi * radius
    filled = (max(0, min(score, 100)) / 100) * circumference
    if score >= 90:
        level, color_var = "ok", "var(--success)"
    elif score >= 60:
        level, color_var = "warn", "var(--warning)"
    else:
        level, color_var = "critical", "var(--critical)"
    return {
        "radius": radius,
        "circumference": f"{circumference:.2f}",
        "filled": f"{filled:.2f}",
        "color": color_var,  # used only in SVG stroke= attributes, not style=
        "level": level,      # used for a CSS class (text color, etc.)
    }


@dashboard_bp.route("/security")
@auth_service.login_required
def security():
    user = auth_service.current_user()
    db = get_db()

    security_score = auth_service.compute_account_security_score(user)
    recent_failed = [
        row for row in audit_service.logs_for_user(db, user["id"], limit=50)
        if row["action"] == audit_service.ACTION_LOGIN and not row["success"]
    ]

    return render_template(
        "security.html",
        user=user,
        security=security_score,
        gauge=_gauge_geometry(security_score["score"]),
        system_security=SYSTEM_SECURITY_CONTROLS,
        is_locked=auth_service.is_account_locked(user),
        failed_login_count=user["failed_login_count"],
        recent_failed=recent_failed[:10],
    )


@dashboard_bp.route("/activity")
@auth_service.login_required
def activity():
    user = auth_service.current_user()
    db = get_db()

    logs = audit_service.logs_for_user(db, user["id"], limit=100)

    return render_template("activity.html", user=user, logs=logs)


@dashboard_bp.route("/settings")
@auth_service.login_required
def settings():
    user = auth_service.current_user()
    return render_template("settings.html", user=user)
