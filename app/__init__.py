import datetime as dt
import os

from flask import Flask, g, request

from app.config import Config
from app.db import init_db, register_teardown
from app.services import csrf as csrf_service
from app.services.encryption_service import load_master_key


def create_app(config_object: type = Config, config_overrides: dict | None = None):
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(config_object)
    if config_overrides:
        app.config.update(config_overrides)

    _validate_secrets(app)

    app.permanent_session_lifetime = dt.timedelta(
        minutes=app.config["PERMANENT_SESSION_LIFETIME_MINUTES"]
    )

    # Trust one hop of X-Forwarded-* headers, for correct client IPs /
    # scheme detection when deployed behind a reverse proxy (nginx, etc.).
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    register_teardown(app)
    init_db(app)

    # Cache the decoded encryption key on the app object (never logged,
    # never persisted, never exposed to templates).
    app.config["_ENCRYPTION_KEY_BYTES"] = load_master_key(app.config["ENCRYPTION_KEY_B64"])

    _register_blueprints(app)
    _register_security_hooks(app)

    return app


def _validate_secrets(app: Flask):
    if app.config.get("TESTING"):
        # Tests provide their own ephemeral secrets via TestConfig/conftest.
        if not app.config.get("SECRET_KEY"):
            app.config["SECRET_KEY"] = os.urandom(32).hex()
        if not app.config.get("ENCRYPTION_KEY_B64"):
            import base64
            app.config["ENCRYPTION_KEY_B64"] = base64.b64encode(os.urandom(32)).decode()
        return

    if not app.config.get("SECRET_KEY"):
        raise RuntimeError(
            "SECUREVAULT_SECRET_KEY environment variable is not set. Refusing to start "
            "with an insecure/default secret key. See .env.example."
        )
    if not app.config.get("ENCRYPTION_KEY_B64"):
        raise RuntimeError(
            "SECUREVAULT_ENCRYPTION_KEY environment variable is not set. Refusing to start. "
            "See .env.example."
        )


def _register_blueprints(app: Flask):
    from app.routes.auth import auth_bp
    from app.routes.files import files_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(admin_bp)


def _register_security_hooks(app: Flask):

    @app.before_request
    def _csrf_protect():
        # Static assets and the small set of read-only, unauthenticated
        # endpoints don't need CSRF validation; every state-changing
        # request does.
        if request.endpoint in ("static",):
            return
        csrf_service.validate_csrf_or_abort()

    @app.context_processor
    def _inject_csrf_token():
        return {"csrf_token": csrf_service.get_or_create_csrf_token}

    @app.context_processor
    def _inject_nav_notifications():
        # Notifications are simply the signed-in user's own most recent
        # audit events -- real data already recorded for security
        # purposes, reused for the topbar rather than a separate
        # invented notification system. No query runs for anonymous
        # visitors (login/register pages).
        from app.services import auth_service as _auth_service
        user = _auth_service.current_user()
        if user is None:
            return {"nav_notifications": []}
        from app.db import get_db as _get_db
        from app.services import audit_service as _audit_service
        db = _get_db()
        return {"nav_notifications": _audit_service.logs_for_user(db, user["id"], limit=5)}

    @app.after_request
    def _set_security_headers(response):
        # Content-Security-Policy: only allow same-origin scripts/styles,
        # no plugins, no framing by other sites, no inline event handlers.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        # Legacy header, harmless to include for older browsers.
        response.headers["X-XSS-Protection"] = "0"

        if app.config.get("ENABLE_HSTS"):
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response

    @app.errorhandler(413)
    def _too_large(_e):
        return {"error": "File exceeds the maximum allowed upload size."}, 413

    @app.errorhandler(403)
    def _forbidden(_e):
        return {"error": "Forbidden"}, 403

    @app.errorhandler(404)
    def _not_found(_e):
        return {"error": "Not found"}, 404
