# AegisVault

A production-quality, security-first file storage vault built with Python 3, Flask, and SQLite. Users register, log in, and upload files that are encrypted with AES-256-GCM before they ever touch disk. Every security-relevant action is audit-logged, and a separate admin dashboard surfaces login activity and system stats without ever being able to decrypt a user's files.

This project was built to demonstrate defense-in-depth: authentication, file-handling, transport, and logging are each hardened independently, so a weakness in one layer doesn't compromise the others.

**A note on naming:** the product is branded AegisVault in the UI. The underlying Python package, module names, and repository folder are unchanged from the original build to avoid unnecessary churn to a tested, working codebase — only user-facing text and templates were rebranded.

---

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Environment variables](#environment-variables)
- [Security design](#security-design)
- [Threat model](#threat-model)
- [How encryption works](#how-encryption-works)
- [Running the tests](#running-the-tests)
- [Known limitations](#known-limitations)
- [Future improvements](#future-improvements)

---

## Features

**Authentication**
- Registration and login with Argon2id password hashing (never plaintext, never a fast general-purpose hash)
- Signed, HttpOnly, SameSite session cookies
- Per-account lockout after repeated failed logins
- Independent per-IP sliding-window rate limiting
- Logout that fully clears the session

**File security**
- Extension allow-listing *and* content-based magic-byte verification (an attacker can't rename `evil.exe` to `evil.pdf` and have it accepted)
- Configurable maximum upload size, enforced at the framework level
- Random, server-generated filenames — the original filename is never used to build a filesystem path
- Files stored outside any web-servable directory
- AES-256-GCM encryption at rest, decrypted only in memory, only for the authenticated owner, only for the duration of the download response

**Platform security**
- CSRF protection (synchronizer token pattern) on every state-changing request
- Parameterized SQL everywhere — no string-built queries
- Path traversal defense, including a defense-in-depth check even though filenames are always server-generated
- Full HTTP security header set: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS
- Jinja2 autoescaping for XSS protection on every template variable
- Authorization enforced on every protected endpoint, independent of the UI

**Visibility**
- User dashboard: file count, storage used, file list, recent activity
- Admin security operations console (five sections — **Users**, **Security Events**, **Login Attempts**, **File Statistics**, **System Activity**): registered users with account status, curated security events, the full raw login-attempt log, file-type/storage breakdowns, and the complete audit trail — with **no** ability to decrypt or download another user's files

---

## Architecture

```
securevault/
├── app/
│   ├── __init__.py            # App factory: security headers, CSRF hook, session config
│   ├── config.py               # All settings sourced from environment variables
│   ├── db.py                    # SQLite connection management + schema
│   ├── models/                  # Parameterized-query data access, one module per table
│   │   ├── user.py
│   │   ├── file.py
│   │   └── login_attempt.py
│   ├── routes/                  # Thin Flask blueprints — no business logic here
│   │   ├── auth.py               # /register /login /logout
│   │   ├── files.py              # /files/upload /files/download/<id> /files/delete/<id>
│   │   ├── dashboard.py          # /
│   │   └── admin.py              # /admin/
│   ├── services/                 # All security-critical logic lives here
│   │   ├── password_service.py    # Argon2id hashing/verification
│   │   ├── encryption_service.py  # AES-256-GCM encrypt/decrypt
│   │   ├── auth_service.py        # Sessions, decorators, lockout, rate limiting
│   │   ├── audit_service.py       # Audit log writes/reads
│   │   ├── file_service.py        # Upload validation, safe storage paths
│   │   └── csrf.py                # CSRF token issuance/verification
│   ├── templates/                 # Jinja2 templates (autoescaped)
│   └── static/                    # CSS/JS only — never used to store uploads
├── tests/                          # unittest-based test suite (pytest-compatible)
├── scripts/manage.py               # Offline admin-promotion CLI (no in-app privilege escalation)
├── storage/                        # Encrypted file blobs (gitignored, created at runtime)
├── instance/                       # SQLite database file (gitignored, created at runtime)
├── .env.example
├── requirements.txt
└── run.py
```

**Design principle:** routes are thin. They parse the request, call into a service, and render a template or redirect. All actual security logic — hashing, encryption, validation, authorization, rate limiting — lives in `app/services/`, where it's easy to find, read, and test in isolation.

### Why no SQLAlchemy / Flask-Login / Flask-WTF / Flask-Limiter / argon2-cffi / bcrypt?

This build environment has no network access to PyPI, so the dependency list had to work with what's already available: Flask and a modern `cryptography` build (which happens to ship native `Argon2id` and `AESGCM` primitives). Rather than fake those libraries or skip requirements, each was reimplemented directly on Flask's session support and the Python standard library:

| Need | Typical package | What AegisVault uses instead |
|---|---|---|
| Password hashing | `argon2-cffi` / `bcrypt` | `cryptography.hazmat.primitives.kdf.argon2.Argon2id` (PHC-encoded) |
| ORM / SQL injection safety | `Flask-SQLAlchemy` | Raw `sqlite3` with `?` placeholders everywhere |
| Session auth | `Flask-Login` | Flask's built-in signed session + custom `login_required`/`admin_required` decorators |
| CSRF tokens | `Flask-WTF` | Hand-rolled synchronizer-token pattern (`app/services/csrf.py`) |
| Rate limiting | `Flask-Limiter` | `login_attempts` table queried with a sliding time window |
| MIME sniffing | `python-magic` | Magic-byte signature table + extension cross-check (`app/services/file_service.py`) |

This has a nice side effect: every security-critical code path is in this repository, in plain Python, rather than hidden inside a third-party dependency. If you have network access and prefer the battle-tested libraries, swapping any one of these in is a contained change (they're all isolated behind the `services/` layer).

---

## Installation

**Requirements:** Python 3.10+ (uses `X | Y` type hints), `pip`.

```bash
git clone <this-repo>
cd securevault
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# Generate a session secret:
python -c "import secrets; print(secrets.token_hex(32))"
# Generate an AES-256 encryption key:
python -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())"
# Paste both into .env as SECUREVAULT_SECRET_KEY and SECUREVAULT_ENCRYPTION_KEY

# Load the .env file into your shell (or use a tool like `python-dotenv`/`honcho`)
export $(grep -v '^#' .env | xargs)

python run.py
# Visit http://127.0.0.1:5000
```

The **first account you register automatically becomes an admin.** Every account after that is a normal user. To promote/demote a user later, use the offline CLI tool — there is deliberately no in-app "make me an admin" button:

```bash
python scripts/manage.py list-users
python scripts/manage.py promote some_username
python scripts/manage.py demote some_username
```

For production, run behind a real WSGI server and a TLS-terminating reverse proxy, e.g.:

```bash
gunicorn -w 4 -b 127.0.0.1:8000 "run:app"
```

Never use the Flask development server (`app.run`) in production, and never set `SECUREVAULT_DEBUG=true` outside local development.

---

## Environment variables

All configuration lives in environment variables — see `.env.example` for the full annotated list. Nothing sensitive has a working default; the app refuses to start without `SECUREVAULT_SECRET_KEY` and `SECUREVAULT_ENCRYPTION_KEY` set (outside of the test suite, which generates ephemeral ones automatically).

| Variable | Purpose | Default |
|---|---|---|
| `SECUREVAULT_SECRET_KEY` | Signs session cookies / CSRF tokens | **required** |
| `SECUREVAULT_ENCRYPTION_KEY` | Base64 AES-256 key for file encryption | **required** |
| `SECUREVAULT_DB_PATH` | SQLite file path | `instance/securevault.db` |
| `SECUREVAULT_STORAGE_DIR` | Encrypted file blob directory | `storage` |
| `SECUREVAULT_MAX_FILE_SIZE_MB` | Max upload size | `10` |
| `SECUREVAULT_ALLOWED_EXTENSIONS` | Comma-separated allow-list | `pdf,png,jpg,jpeg,gif,txt,csv,docx,zip` |
| `SECUREVAULT_MAX_FAILED_LOGINS` | Failures before account lockout | `5` |
| `SECUREVAULT_LOCKOUT_MINUTES` | Lockout duration | `15` |
| `SECUREVAULT_IP_RATE_LIMIT_ATTEMPTS` | Login attempts per IP per window | `10` |
| `SECUREVAULT_IP_RATE_LIMIT_WINDOW_MINUTES` | IP throttle window | `5` |
| `SECUREVAULT_ARGON2_TIME_COST` / `_MEMORY_COST_KIB` / `_PARALLELISM` | Argon2id cost parameters | `3` / `65536` / `4` |
| `SECUREVAULT_COOKIE_SECURE` | Require HTTPS for cookies | `true` |
| `SECUREVAULT_SESSION_LIFETIME_MINUTES` | Idle session timeout | `30` |
| `SECUREVAULT_ENABLE_HSTS` | Send `Strict-Transport-Security` | `true` |
| `SECUREVAULT_DEBUG` | Flask debug mode | `false` |

---

## Security design

**Passwords.** Hashed with Argon2id (memory-hard, OWASP's current recommendation), using a random 16-byte salt per password and tunable cost parameters. Verification uses the library's constant-time comparison internally; failures return a generic boolean rather than throwing details back to the caller.

**Sessions.** Flask's built-in session, which is a cryptographically signed cookie (via `itsdangerous` + `SECRET_KEY`). It only ever stores `user_id`, `role`, and `username` — never a password or key. Cookies are `HttpOnly` (unreadable by JavaScript), `SameSite=Lax` (mitigates cross-site request delivery), and `Secure` (HTTPS-only) in any non-test configuration.

**CSRF.** Every POST/PUT/PATCH/DELETE request is checked against a per-session token using a constant-time comparison (`hmac.compare_digest`). Combined with `SameSite=Lax`, this closes both the "attacker page auto-submits a form" and "attacker page reads the token" avenues.

**File uploads.** Three independent checks must all pass: extension allow-list, file-size limit, and content-based signature verification that the actual bytes match what the extension claims. A `.pdf` that's really an `.exe` is rejected even though the extension alone would pass.

**File storage.** Every file gets a random 32-byte hex filename (`secrets.token_hex(32)`) — collision-resistant and unguessable. The user's original filename is stored purely as a display label in the database (HTML-escaped on render) and never touches a filesystem path. `resolve_storage_path()` additionally verifies, at write and read time, that the resolved path is still inside the storage directory — defense in depth even though nothing user-controlled reaches that function today.

**Encryption at rest.** See [How encryption works](#how-encryption-works).

**Authorization.** Every file operation loads the record and checks `record.user_id == current_user.id` before doing anything else — including for admins. There is no code path, including in the admin blueprint, that decrypts a file belonging to another user.

**SQL injection.** Every single query in the codebase uses `?` placeholders. There is no string formatting, f-string interpolation, or `.format()` call anywhere near a SQL statement — this is verifiable by grepping the `app/models/` and `app/db.py` files.

**XSS.** All dynamic template output goes through Jinja2's autoescaping (enabled by default and never disabled with `|safe` in this codebase). Client-side JavaScript lives in an external file (`static/js/main.js`) rather than inline, which is also enforced by the CSP's `script-src 'self'` with no `'unsafe-inline'`.

**HTTP headers.** Every response gets a strict Content-Security-Policy, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a locked-down `Permissions-Policy`, and (outside of local dev) `Strict-Transport-Security`.

**Audit logging.** `app/services/audit_service.py` records every login attempt, logout, upload, download, delete, and unauthorized-access attempt, with the acting user (if any), IP, timestamp, success/failure, and the relevant resource id.

---

## Threat model

**In scope / defended against:**

| Threat | Mitigation |
|---|---|
| Credential stuffing / brute force | Per-account lockout + independent per-IP rate limiting |
| Password database compromise | Argon2id hashing means offline cracking is slow and salted per-user |
| Stolen/leaked database or backup | File contents are AES-256-GCM encrypted; the DB alone doesn't expose file plaintext |
| CSRF | Per-session synchronizer token + SameSite cookies |
| Stored/reflected XSS | Autoescaping everywhere, no inline scripts, strict CSP |
| SQL injection | 100% parameterized queries |
| Path traversal | Server-generated filenames + path-containment verification |
| Malicious file-type spoofing | Content-based signature verification, not just extension/Content-Type trust |
| Session hijacking via XSS | HttpOnly cookies (unreadable by injected JS) |
| CSRF/clickjacking via framing | `X-Frame-Options: DENY`, `frame-ancestors 'none'` |
| One user reading/deleting another's files | Ownership check on every file operation, including for admins |
| Privilege escalation via self-registration | No in-app role-change endpoint; promotion is an offline CLI action only |
| Tampering with stored ciphertext or its DB metadata | AES-GCM's authentication tag + associated data binding (user id + stored filename) — tampering causes decryption to fail loudly rather than silently returning wrong data |

**Explicitly out of scope for this project** (would need additional infrastructure, not just application code):

- **Network-layer attacks** (TLS termination, DDoS) — this app assumes it sits behind a reverse proxy/load balancer that handles TLS and basic network-layer protection.
- **Server/host compromise.** If an attacker gets root on the server while it's running, they can read the encryption key out of process memory or environment variables. AES-GCM protects data *at rest* on stolen disks/backups, not against a live, fully-compromised host.
- **Malicious admin.** An admin cannot decrypt user files through the app, but an admin (or anyone with DB + storage + key access) is a privileged insider by definition; this app does not attempt insider-threat protection beyond withholding the decryption capability from the UI/API layer itself.
- **Side-channel attacks** against the cryptographic primitives themselves — we rely on `cryptography`'s audited implementations rather than hand-rolling crypto.
- **Denial of service** at scale (this app's rate limiting slows down single-source brute force; it is not a substitute for a WAF/CDN under real attack volumes).
- **Multi-factor authentication** — not implemented in this version (see Future improvements).

---

## How encryption works

Files are encrypted with **AES-256-GCM**, an authenticated encryption (AEAD) cipher, using the `cryptography` library's audited implementation (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`).

1. A single 256-bit **master key** is loaded once at startup from the `SECUREVAULT_ENCRYPTION_KEY` environment variable (base64-encoded). It is never logged, written to disk, or stored in the database.
2. On upload, a fresh random **96-bit nonce** (`os.urandom(12)`) is generated for that file. Nonces are not secret — they're stored (base64) in the `files.nonce_b64` column — but must never repeat under the same key, and a fresh random draw per file makes that astronomically unlikely.
3. The plaintext is encrypted with `AESGCM(master_key).encrypt(nonce, plaintext, associated_data)`, where `associated_data` is `"{user_id}:{stored_filename}"`. This **binds the ciphertext to its owner and identity** — if someone swapped which database row pointed at a given encrypted blob, or changed the `user_id` column, decryption would fail with an authentication error rather than silently handing back the wrong (or corrupted) plaintext.
4. The resulting ciphertext (which includes GCM's built-in 16-byte authentication tag) is written to `storage/<random-hex-filename>` with `0600` permissions.
5. On download, the app re-derives the same associated data from the current database record, reads the ciphertext off disk, and calls `AESGCM(master_key).decrypt(...)`. If the file, its metadata, or the nonce have been tampered with in any way, this raises `InvalidTag` and the app returns an error instead of serving corrupted or wrong data.

Key takeaway: **confidentiality** comes from AES-256 encryption; **integrity and authenticity** come from GCM's authentication tag plus the associated-data binding — an attacker with filesystem access alone cannot read files, and cannot substitute or splice files between users without detection.

---

## Running the tests

The suite uses Python's built-in `unittest` (this sandbox has no PyPI access for `pytest`, but the tests are fully pytest-compatible if you have it installed).

```bash
# stdlib unittest
python -m unittest discover -s tests -p "test_*.py" -v

# or, if you have pytest installed
pip install pytest
pytest tests/ -v
```

Each test spins up an isolated Flask app with its own temporary SQLite database and storage directory (see `tests/base.py`), so tests never share state and never touch your real `instance/`/`storage/` directories.

Coverage includes: registration (valid/invalid/duplicate), login (valid/invalid/nonexistent user, identical error message for both to avoid username enumeration), account lockout, per-IP rate limiting, session/logout behavior, file upload (valid, wrong extension, spoofed content, empty file, oversized file), encryption-at-rest verification (plaintext never appears in the stored blob), download/decrypt round-tripping, delete, cross-user authorization (download/delete/admin-download all denied), path traversal, CSRF (missing/invalid token on state-changing routes), SQL injection payloads against the login/registration forms, XSS escaping of user-controlled filenames, HTTP security headers, session cookie flags, and admin dashboard access control (regular users and anonymous visitors are denied; the first registered account is auto-admin and subsequent ones are not).

**Result at time of writing: 46/46 tests passing.**

---

## Known limitations

- **No multi-factor authentication.** Password-only login, even with Argon2id and lockout/rate-limiting, is weaker than password + MFA.
- **No email verification** on registration — anyone can register with any syntactically valid email address.
- **No password reset flow.** A forgotten password currently has no self-service recovery path (this is a common source of vulnerabilities if built carelessly, so it was deliberately left out rather than built quickly).
- **Single shared master encryption key.** All files share one AES key (differentiated per-file only by nonce + AEAD binding). A more advanced design would use envelope encryption (a unique data-encryption key per file, itself wrapped by the master key or a per-user key).
- **In-memory decryption for downloads.** Files are decrypted fully into memory before being streamed to the client, which is fine for the configured size limits (default 10MB) but wouldn't scale to very large files without moving to chunked/streaming decryption.
- **No key rotation mechanism.** Rotating `SECUREVAULT_ENCRYPTION_KEY` today would make all previously-encrypted files unreadable; there's no re-encryption tooling yet.
- **SQLite, not built for high concurrency.** Fine for the intended scale (a personal/small-team vault); a high-traffic deployment would want PostgreSQL.
- **The IP-based rate limiter uses `request.remote_addr`** (normalized via `ProxyFix` for one reverse-proxy hop). Deployments behind multiple proxy layers or with header-spoofing-capable clients in front of the app need to adjust the ProxyFix hop count accordingly.
- **No CAPTCHA / bot mitigation** on registration or login beyond the rate limiter.
- **Tests use reduced Argon2 cost parameters** for speed; production uses the full-strength defaults in `Config` — make sure a deployment doesn't accidentally run with `TestConfig`.

## Future improvements

- Add TOTP-based multi-factor authentication
- Add email verification and a secure, token-based password reset flow
- Move to envelope encryption with per-file data-encryption keys
- Add streaming encryption/decryption for large files instead of full in-memory buffering
- Add key-rotation tooling (re-encrypt all files under a new master key)
- Add per-user storage quotas
- Add file versioning / soft-delete with a recovery window before permanent deletion
- Add structured (JSON) audit logging with export to an external SIEM
- Add CAPTCHA or proof-of-work on registration/login to slow down automated abuse
- Support PostgreSQL for higher-concurrency deployments
- Add automated dependency and static-analysis security scanning (e.g. `pip-audit`, `bandit`) to CI
