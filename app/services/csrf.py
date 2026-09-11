"""
CSRF protection.

We implement the "synchronizer token" pattern by hand:
  * A random token is generated once per session and stored server-side
    in the (signed, httponly) session cookie.
  * Every state-changing form includes that token as a hidden field
    (or an X-CSRF-Token header for JSON/AJAX requests).
  * On every POST/PUT/PATCH/DELETE, we compare the submitted token to the
    one in the session using a constant-time comparison (hmac.compare_digest)
    to avoid timing side-channels.

Combined with SameSite=Lax cookies, this defends against classic CSRF:
an attacker's cross-site page cannot read the token out of our session
cookie (httponly + same-origin), and cannot forge it.
"""
import hmac
import secrets

from flask import session, request, abort

CSRF_SESSION_KEY = "_csrf_token"
FORM_FIELD_NAME = "csrf_token"
HEADER_NAME = "X-CSRF-Token"


def get_or_create_csrf_token() -> str:
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def _submitted_token() -> str | None:
    if request.form and FORM_FIELD_NAME in request.form:
        return request.form.get(FORM_FIELD_NAME)
    if request.headers.get(HEADER_NAME):
        return request.headers.get(HEADER_NAME)
    if request.is_json:
        data = request.get_json(silent=True) or {}
        return data.get(FORM_FIELD_NAME)
    return None


def validate_csrf_or_abort():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    expected = session.get(CSRF_SESSION_KEY)
    provided = _submitted_token()
    if not expected or not provided or not hmac.compare_digest(expected, provided):
        abort(400, description="Invalid or missing CSRF token")
