"""
Authentication/session helpers.

Session management: we rely on Flask's built-in session, which is a
cryptographically signed (via itsdangerous + SECRET_KEY) cookie. The
cookie is HttpOnly, SameSite=Lax, and Secure (see config.py), and only
ever stores the user's id and role -- never the password hash or any
secret material. Because it's signed, a client cannot forge or tamper
with it without knowing SECRET_KEY.

Rate limiting / account lockout strategy (defense in depth, two layers):
  1. Per-account lockout: after MAX_FAILED_LOGINS consecutive failures
     for a given username, that account is locked for LOCKOUT_MINUTES,
     regardless of source IP (protects a targeted account).
  2. Per-IP sliding-window throttle: if a single IP produces more than
     IP_RATE_LIMIT_ATTEMPTS login attempts within IP_RATE_LIMIT_WINDOW_MINUTES,
     further attempts from that IP are rejected with 429 (slows down
     username enumeration / credential stuffing sweeps across many
     accounts from one source).
"""
import datetime as dt
from functools import wraps

from flask import session, g, current_app, redirect, url_for, request, abort, flash

from app.db import get_db
from app.models import user as user_model
from app.models import login_attempt as login_attempt_model
from app.models import mfa as mfa_model


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def get_client_ip() -> str:
    # In production this app should sit behind a trusted reverse proxy
    # that sets X-Forwarded-For; Werkzeug's ProxyFix (wired up in
    # app/__init__.py) normalizes request.remote_addr for us. We
    # deliberately do NOT trust arbitrary client-supplied headers here.
    return request.remote_addr or "unknown"


def login_user(user_row) -> None:
    session.clear()
    session.permanent = True
    session["user_id"] = user_row["id"]
    session["role"] = user_row["role"]
    session["username"] = user_row["username"]


def begin_mfa(user_row) -> None:
    session.clear()
    session.permanent = True
    session["mfa_user_id"] = user_row["id"]


def pending_mfa_user():
    user_id = session.get("mfa_user_id")
    if user_id is None:
        return None
    return user_model.get_user_by_id(get_db(), user_id)


def clear_pending_mfa() -> None:
    session.pop("mfa_user_id", None)


def mfa_rate_limited(db, *, user_id: int, ip_address: str) -> bool:
    cfg = current_app.config
    since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(
        minutes=cfg["MFA_RATE_LIMIT_WINDOW_MINUTES"]
    )).isoformat()
    return mfa_model.count_recent_failures(
        db, user_id=user_id, ip_address=ip_address, since_iso=since
    ) >= cfg["MFA_RATE_LIMIT_ATTEMPTS"]


def logout_user() -> None:
    session.clear()


def current_user():
    if "user" in g:
        return g.user
    user_id = session.get("user_id")
    if user_id is None:
        g.user = None
        return None
    db = get_db()
    g.user = user_model.get_user_by_id(db, user_id)
    return g.user


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            if request.accept_mimetypes.best == "application/json":
                abort(401)
            flash("Please log in to continue.", "error")
            return redirect(url_for("auth.login"))
        return view_func(*args, **kwargs)
    return wrapped


def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            flash("Please log in to continue.", "error")
            return redirect(url_for("auth.login"))
        if user["role"] != "admin":
            abort(403)
        return view_func(*args, **kwargs)
    return wrapped


# --------------------------------------------------------------------------
# Rate limiting / lockout
# --------------------------------------------------------------------------

def is_ip_rate_limited(db, ip_address: str) -> bool:
    cfg = current_app.config
    window_start = (
        dt.datetime.now(dt.timezone.utc)
        - dt.timedelta(minutes=cfg["IP_RATE_LIMIT_WINDOW_MINUTES"])
    ).isoformat()
    count = login_attempt_model.count_attempts_since(db, ip_address=ip_address, since_iso=window_start)
    return count >= cfg["IP_RATE_LIMIT_ATTEMPTS"]


def is_account_locked(user_row) -> bool:
    if not user_row or not user_row["locked_until"]:
        return False
    locked_until = dt.datetime.fromisoformat(user_row["locked_until"])
    return dt.datetime.now(dt.timezone.utc) < locked_until


def register_failed_login(db, user_row) -> None:
    """Increment failure count and lock the account if the threshold is hit."""
    cfg = current_app.config
    if user_row is None:
        return
    new_count = user_row["failed_login_count"] + 1
    locked_until = None
    if new_count >= cfg["MAX_FAILED_LOGINS"]:
        locked_until = (
            dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=cfg["LOCKOUT_MINUTES"])
        ).isoformat()
    user_model.update_failed_login(db, user_id=user_row["id"], failed_count=new_count, locked_until=locked_until)


def reset_failed_login(db, user_row) -> None:
    if user_row is None:
        return
    user_model.update_failed_login(db, user_id=user_row["id"], failed_count=0, locked_until=None)


def compute_account_security_score(user_row) -> dict:
    """A small, transparent score derived entirely from real signals already
    tracked on the user record (current lockout state and failed-login
    count) -- NOT a simulated or invented "system health" number. The
    dashboard labels this explicitly as an account-level signal, not a
    claim about overall platform security (which is a fixed set of
    always-on controls, shown separately).
    """
    score = 100
    if is_account_locked(user_row):
        score -= 45
    score -= min((user_row["failed_login_count"] or 0) * 8, 40)
    score = max(score, 5)

    if score >= 90:
        label = "SYSTEM SECURE"
    elif score >= 60:
        label = "ATTENTION RECOMMENDED"
    else:
        label = "ACTION REQUIRED"

    return {"score": score, "label": label}
