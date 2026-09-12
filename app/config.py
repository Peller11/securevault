"""
Application configuration.

ALL secrets and tunable security parameters are read from environment
variables. Nothing sensitive is hardcoded here, and there are no
insecure defaults for secrets -- if a required secret is missing in a
non-testing context, the app refuses to start (see __init__.py).
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _bool_env(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


class Config:
    # --- Core Flask / session secrets -------------------------------------
    # Used to sign session cookies and CSRF tokens (via itsdangerous).
    SECRET_KEY = os.environ.get("SECUREVAULT_SECRET_KEY")

    # Base64-encoded 32-byte key used for AES-256-GCM file encryption.
    # Generate with: python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
    ENCRYPTION_KEY_B64 = os.environ.get("SECUREVAULT_ENCRYPTION_KEY")

    # --- Storage locations ---------------------------------------------
    # SQLite database file. Kept outside of app/static and app/templates.
    DATABASE_PATH = os.environ.get(
        "SECUREVAULT_DB_PATH", str(BASE_DIR / "instance" / "securevault.db")
    )

    # Directory where ENCRYPTED file blobs are stored. This directory is
    # NOT served by Flask's static file handler and is not reachable via
    # any route -- files are only ever streamed back through the
    # authenticated /files/download/<id> endpoint after decryption.
    STORAGE_DIR = os.environ.get(
        "SECUREVAULT_STORAGE_DIR", str(BASE_DIR / "storage")
    )

    # --- Upload policy ----------------------------------------------------
    MAX_FILE_SIZE_MB = int(os.environ.get("SECUREVAULT_MAX_FILE_SIZE_MB", "10"))
    MAX_CONTENT_LENGTH = MAX_FILE_SIZE_MB * 1024 * 1024

    ALLOWED_EXTENSIONS = set(
        e.strip().lower()
        for e in os.environ.get(
            "SECUREVAULT_ALLOWED_EXTENSIONS",
            "pdf,png,jpg,jpeg,gif,txt,csv,docx,zip",
        ).split(",")
        if e.strip()
    )

    # --- Auth / lockout policy --------------------------------------------
    MAX_FAILED_LOGINS = int(os.environ.get("SECUREVAULT_MAX_FAILED_LOGINS", "5"))
    LOCKOUT_MINUTES = int(os.environ.get("SECUREVAULT_LOCKOUT_MINUTES", "15"))
    # Sliding-window IP based throttle (independent of per-account lockout)
    IP_RATE_LIMIT_ATTEMPTS = int(os.environ.get("SECUREVAULT_IP_RATE_LIMIT_ATTEMPTS", "10"))
    IP_RATE_LIMIT_WINDOW_MINUTES = int(
        os.environ.get("SECUREVAULT_IP_RATE_LIMIT_WINDOW_MINUTES", "5")
    )
    MFA_RATE_LIMIT_ATTEMPTS = int(os.environ.get("SECUREVAULT_MFA_RATE_LIMIT_ATTEMPTS", "5"))
    MFA_RATE_LIMIT_WINDOW_MINUTES = int(
        os.environ.get("SECUREVAULT_MFA_RATE_LIMIT_WINDOW_MINUTES", "5")
    )
    MFA_RECOVERY_CODE_COUNT = 10

    # --- Argon2id parameters ------------------------------------------
    ARGON2_TIME_COST = int(os.environ.get("SECUREVAULT_ARGON2_TIME_COST", "3"))
    ARGON2_MEMORY_COST_KIB = int(os.environ.get("SECUREVAULT_ARGON2_MEMORY_COST_KIB", str(64 * 1024)))
    ARGON2_PARALLELISM = int(os.environ.get("SECUREVAULT_ARGON2_PARALLELISM", "4"))

    # --- Cookie / transport security ---------------------------------------
    # Secure cookies require HTTPS. Default ON; only disable explicitly for
    # local plain-HTTP development.
    SESSION_COOKIE_SECURE = _bool_env("SECUREVAULT_COOKIE_SECURE", True)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME_MINUTES = int(
        os.environ.get("SECUREVAULT_SESSION_LIFETIME_MINUTES", "30")
    )

    # Whether to send HSTS headers (should be True whenever served over HTTPS)
    ENABLE_HSTS = _bool_env("SECUREVAULT_ENABLE_HSTS", True)

    DEBUG = _bool_env("SECUREVAULT_DEBUG", False)
    TESTING = False


class TestConfig(Config):
    """Configuration used by the automated test-suite."""
    TESTING = True
    DEBUG = True
    WTF_CSRF_ENABLED = True
    # Tests run over the Werkzeug test client (no real TLS), so we relax
    # the Secure cookie flag purely so the test client's cookie jar behaves
    # predictably; this is NEVER the default for real deployments.
    SESSION_COOKIE_SECURE = False
    ENABLE_HSTS = False
    MAX_FAILED_LOGINS = 3
    LOCKOUT_MINUTES = 1
    IP_RATE_LIMIT_ATTEMPTS = 12
    IP_RATE_LIMIT_WINDOW_MINUTES = 1
    # Cheaper Argon2 parameters so the test-suite runs quickly. Production
    # MUST use the stronger defaults in Config.
    ARGON2_TIME_COST = 1
    ARGON2_MEMORY_COST_KIB = 8 * 1024
    ARGON2_PARALLELISM = 1
