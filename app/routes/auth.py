import base64
import io
import re

import pyotp
import qrcode
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app

from app.db import get_db
from app.models import user as user_model
from app.models import login_attempt as login_attempt_model
from app.services import password_service, audit_service, auth_service
from app.models import mfa as mfa_model

auth_bp = Blueprint("auth", __name__)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _validate_registration(username, email, password, confirm_password):
    errors = []
    if not USERNAME_RE.match(username or ""):
        errors.append("Username must be 3-32 characters: letters, numbers, underscores only.")
    if not EMAIL_RE.match(email or ""):
        errors.append("Please enter a valid email address.")
    if not password or len(password) < 10:
        errors.append("Password must be at least 10 characters long.")
    if password != confirm_password:
        errors.append("Passwords do not match.")
    return errors


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if auth_service.current_user():
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        errors = _validate_registration(username, email, password, confirm_password)
        db = get_db()

        if not errors:
            if user_model.get_user_by_username(db, username):
                errors.append("That username is already taken.")
            if user_model.get_user_by_email(db, email):
                errors.append("That email is already registered.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register.html", username=username, email=email), 400

        cfg = current_app.config
        password_hash = password_service.hash_password(
            password,
            time_cost=cfg["ARGON2_TIME_COST"],
            memory_cost_kib=cfg["ARGON2_MEMORY_COST_KIB"],
            parallelism=cfg["ARGON2_PARALLELISM"],
        )
        # First-ever account becomes admin automatically so the system is
        # usable out of the box; every subsequent registration is a normal
        # user. Further promotions require the offline `scripts/manage.py`
        # tool -- there is no self-service "become admin" endpoint.
        role = "admin" if user_model.count_users(db) == 0 else "user"
        new_user = user_model.create_user(
            db, username=username, email=email, password_hash=password_hash, role=role
        )
        audit_service.log_action(
            user_id=new_user["id"],
            action=audit_service.ACTION_REGISTER,
            ip_address=auth_service.get_client_ip(),
            success=True,
        )
        flash("Account created. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html", username="", email="")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if auth_service.current_user():
        return redirect(url_for("dashboard.index"))
    if auth_service.pending_mfa_user():
        return redirect(url_for("auth.mfa_verify"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        ip_address = auth_service.get_client_ip()
        db = get_db()

        if auth_service.is_ip_rate_limited(db, ip_address):
            audit_service.log_action(
                user_id=None, action=audit_service.ACTION_LOGIN,
                ip_address=ip_address, success=False, resource_id=username,
            )
            flash("Too many login attempts from this network. Please try again later.", "error")
            return render_template("login.html", username=username), 429

        user_row = user_model.get_user_by_username(db, username)

        if user_row and auth_service.is_account_locked(user_row):
            login_attempt_model.record_attempt(db, username_attempted=username, ip_address=ip_address, success=False)
            audit_service.log_action(
                user_id=user_row["id"], action=audit_service.ACTION_LOGIN,
                ip_address=ip_address, success=False, resource_id="locked",
            )
            flash("This account is temporarily locked due to repeated failed logins. Try again later.", "error")
            return render_template("login.html", username=username), 423

        password_ok = user_row is not None and password_service.verify_password(password, user_row["password_hash"])

        login_attempt_model.record_attempt(db, username_attempted=username, ip_address=ip_address, success=password_ok)

        if not password_ok:
            if user_row is not None:
                auth_service.register_failed_login(db, user_row)
            audit_service.log_action(
                user_id=user_row["id"] if user_row else None,
                action=audit_service.ACTION_LOGIN, ip_address=ip_address, success=False,
            )
            # Deliberately identical error whether the username exists or
            # not, to avoid leaking which usernames are registered.
            flash("Invalid username or password.", "error")
            return render_template("login.html", username=username), 401

        auth_service.reset_failed_login(db, user_row)
        if user_row["mfa_enabled"]:
            auth_service.begin_mfa(user_row)
            return redirect(url_for("auth.mfa_verify"))
        auth_service.login_user(user_row)
        audit_service.log_action(
            user_id=user_row["id"], action=audit_service.ACTION_LOGIN,
            ip_address=ip_address, success=True,
        )
        return redirect(url_for("dashboard.index"))

    return render_template("login.html", username="")


@auth_bp.route("/logout", methods=["POST"])
def logout():
    user = auth_service.current_user()
    if user:
        audit_service.log_action(
            user_id=user["id"], action=audit_service.ACTION_LOGOUT,
            ip_address=auth_service.get_client_ip(), success=True,
        )
    auth_service.logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))


def _mfa_qr_data_uri(user, secret):
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=user["email"], issuer_name="AegisVault"
    )
    image = qrcode.make(uri)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return "data:image/png;base64," + base64.b64encode(output.getvalue()).decode("ascii")


def _verify_mfa_factor(db, user, code: str):
    if user["mfa_secret"] and pyotp.TOTP(user["mfa_secret"]).verify(code or "", valid_window=1):
        return "totp"
    if mfa_model.consume_recovery_code(db, user_id=user["id"], code=code):
        return "recovery"
    return None


@auth_bp.route("/mfa/setup", methods=["GET", "POST"])
@auth_service.login_required
def mfa_setup():
    user = auth_service.current_user()
    db = get_db()
    if user["mfa_enabled"]:
        return redirect(url_for("dashboard.security"))

    secret = user["mfa_secret"] or pyotp.random_base32()
    if not user["mfa_secret"]:
        user_model.set_mfa_secret(db, user_id=user["id"], secret=secret, enabled=False)
        user = user_model.get_user_by_id(db, user["id"])

    if request.method == "POST":
        code = request.form.get("code") or ""
        if not (code.isdigit() and len(code) == 6 and pyotp.TOTP(secret).verify(code, valid_window=1)):
            audit_service.log_action(
                user_id=user["id"], action=audit_service.ACTION_MFA_VERIFY,
                ip_address=auth_service.get_client_ip(), success=False,
            )
            flash("Enter the current 6-digit code from your authenticator app.", "error")
        else:
            user_model.set_mfa_secret(db, user_id=user["id"], secret=secret, enabled=True)
            recovery_codes = mfa_model.generate_recovery_codes(current_app.config["MFA_RECOVERY_CODE_COUNT"])
            mfa_model.replace_recovery_codes(db, user_id=user["id"], codes=recovery_codes)
            audit_service.log_action(
                user_id=user["id"], action=audit_service.ACTION_MFA_ENABLED,
                ip_address=auth_service.get_client_ip(), success=True,
            )
            return render_template(
                "mfa_setup.html", user=user, secret=secret,
                qr_data_uri=_mfa_qr_data_uri(user, secret), enabled=True,
                recovery_codes=recovery_codes,
            )

    return render_template(
        "mfa_setup.html", user=user, secret=secret,
        qr_data_uri=_mfa_qr_data_uri(user, secret), enabled=False,
        recovery_codes=None,
    )


@auth_bp.route("/mfa/verify", methods=["GET", "POST"])
def mfa_verify():
    if auth_service.current_user():
        return redirect(url_for("dashboard.index"))
    user = auth_service.pending_mfa_user()
    if user is None or not user["mfa_enabled"]:
        auth_service.clear_pending_mfa()
        return redirect(url_for("auth.login"))

    db = get_db()
    ip_address = auth_service.get_client_ip()
    if request.method == "POST":
        if auth_service.mfa_rate_limited(db, user_id=user["id"], ip_address=ip_address):
            audit_service.log_action(
                user_id=user["id"], action=audit_service.ACTION_MFA_VERIFY,
                ip_address=ip_address, success=False,
            )
            flash("Too many MFA attempts. Please try again later.", "error")
            return render_template("mfa_verify.html", username=user["username"]), 429
        factor = _verify_mfa_factor(db, user, request.form.get("code") or "")
        mfa_model.record_attempt(db, user_id=user["id"], ip_address=ip_address, success=bool(factor))
        audit_service.log_action(
            user_id=user["id"], action=audit_service.ACTION_MFA_VERIFY,
            ip_address=ip_address, success=bool(factor),
        )
        if factor:
            if factor == "recovery":
                audit_service.log_action(
                    user_id=user["id"], action=audit_service.ACTION_MFA_RECOVERY_USED,
                    ip_address=ip_address, success=True,
                )
            auth_service.clear_pending_mfa()
            auth_service.login_user(user)
            audit_service.log_action(
                user_id=user["id"], action=audit_service.ACTION_LOGIN,
                ip_address=ip_address, success=True,
            )
            return redirect(url_for("dashboard.index"))
        flash("Invalid authentication code.", "error")
        return render_template("mfa_verify.html", username=user["username"]), 401

    return render_template("mfa_verify.html", username=user["username"])


@auth_bp.route("/mfa/recovery-codes/regenerate", methods=["POST"])
@auth_service.login_required
def regenerate_recovery_codes():
    user = auth_service.current_user()
    db = get_db()
    if not user["mfa_enabled"]:
        return redirect(url_for("dashboard.security"))
    if not password_service.verify_password(request.form.get("password") or "", user["password_hash"]):
        flash("Re-authentication failed.", "error")
        return redirect(url_for("dashboard.security"))
    factor = _verify_mfa_factor(db, user, request.form.get("code") or "")
    if not factor:
        flash("A valid authenticator or recovery code is required.", "error")
        return redirect(url_for("dashboard.security"))
    codes = mfa_model.generate_recovery_codes(current_app.config["MFA_RECOVERY_CODE_COUNT"])
    mfa_model.replace_recovery_codes(db, user_id=user["id"], codes=codes)
    audit_service.log_action(
        user_id=user["id"], action=audit_service.ACTION_MFA_RECOVERY_REGENERATED,
        ip_address=auth_service.get_client_ip(), success=True,
    )
    return render_template("recovery_codes.html", recovery_codes=codes)


@auth_bp.route("/mfa/disable", methods=["POST"])
@auth_service.login_required
def disable_mfa():
    user = auth_service.current_user()
    db = get_db()
    password_ok = password_service.verify_password(request.form.get("password") or "", user["password_hash"])
    factor = _verify_mfa_factor(db, user, request.form.get("code") or "") if password_ok else None
    success = bool(user["mfa_enabled"] and password_ok and factor)
    audit_service.log_action(
        user_id=user["id"], action=audit_service.ACTION_MFA_DISABLED,
        ip_address=auth_service.get_client_ip(), success=success,
    )
    if not success:
        flash("Current password and a valid authenticator or recovery code are required.", "error")
        return redirect(url_for("dashboard.security"))
    user_model.set_mfa_secret(db, user_id=user["id"], secret=None, enabled=False)
    db.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user["id"],))
    db.commit()
    flash("Multi-factor authentication disabled.", "success")
    return redirect(url_for("dashboard.security"))
