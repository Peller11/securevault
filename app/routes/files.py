import io

from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, send_file, abort

from app.db import get_db
from app.models import file as file_model
from app.services import auth_service, audit_service, file_service
from app.services.encryption_service import encrypt_bytes, decrypt_bytes, DecryptionError
from app.services.file_service import FileValidationError

files_bp = Blueprint("files", __name__, url_prefix="/files")


def _safe_redirect_target():
    """Return the page to redirect back to after an upload/delete. Only
    ever redirects to a route within this app that we've explicitly
    listed -- never to an arbitrary user-supplied URL -- to avoid an
    open-redirect vector."""
    target = request.form.get("next")
    allowed = {url_for("dashboard.index"), url_for("files.index")}
    return target if target in allowed else url_for("dashboard.index")


@files_bp.route("/", methods=["GET"])
@auth_service.login_required
def index():
    user = auth_service.current_user()
    db = get_db()
    files = file_model.list_files_for_user(db, user["id"])
    total_bytes = file_model.total_storage_bytes_for_user(db, user["id"])
    extensions = sorted({
        f["original_filename"].rsplit(".", 1)[-1].lower()
        for f in files if "." in f["original_filename"]
    })
    return render_template(
        "files.html", files=files, file_count=len(files),
        total_bytes=total_bytes, file_extensions=extensions,
    )


@files_bp.route("/upload", methods=["POST"])
@auth_service.login_required
def upload():
    user = auth_service.current_user()
    db = get_db()
    cfg = current_app.config
    ip = auth_service.get_client_ip()

    upload_obj = request.files.get("file")
    if upload_obj is None or upload_obj.filename == "":
        flash("Please choose a file to upload.", "error")
        return redirect(_safe_redirect_target())

    content = upload_obj.read()

    try:
        mime_type = file_service.validate_upload(
            upload_obj.filename,
            content,
            allowed_extensions=cfg["ALLOWED_EXTENSIONS"],
            max_size_bytes=cfg["MAX_CONTENT_LENGTH"],
        )
    except FileValidationError as exc:
        audit_service.log_action(
            user_id=user["id"], action=audit_service.ACTION_UPLOAD,
            ip_address=ip, success=False, resource_id=None,
        )
        flash(str(exc), "error")
        return redirect(_safe_redirect_target())

    stored_filename = file_service.generate_stored_filename()
    # Original filename is sanitized to a safe display label ONLY -- it is
    # never used to construct a filesystem path.
    display_name = upload_obj.filename.strip()[:255]

    ciphertext, nonce_b64 = encrypt_bytes(
        cfg["_ENCRYPTION_KEY_BYTES"], content, user_id=user["id"], stored_filename=stored_filename
    )

    try:
        file_service.write_encrypted_file(cfg["STORAGE_DIR"], stored_filename, ciphertext)
    except FileValidationError as exc:
        flash(str(exc), "error")
        return redirect(_safe_redirect_target())

    record = file_model.create_file(
        db,
        user_id=user["id"],
        stored_filename=stored_filename,
        original_filename=display_name,
        mime_type=mime_type,
        size_bytes=len(content),
        nonce_b64=nonce_b64,
    )

    audit_service.log_action(
        user_id=user["id"], action=audit_service.ACTION_UPLOAD,
        ip_address=ip, success=True, resource_id=record["id"],
    )
    flash(f'Uploaded "{display_name}".', "success")
    return redirect(_safe_redirect_target())


def _load_owned_file_or_none(db, file_id: int, user):
    record = file_model.get_file_by_id(db, file_id)
    if record is None:
        return None
    if record["user_id"] != user["id"]:
        return "forbidden"
    return record


@files_bp.route("/download/<int:file_id>", methods=["GET"])
@auth_service.login_required
def download(file_id: int):
    user = auth_service.current_user()
    db = get_db()
    cfg = current_app.config
    ip = auth_service.get_client_ip()

    result = _load_owned_file_or_none(db, file_id, user)

    if result is None:
        abort(404)
    if result == "forbidden":
        audit_service.log_action(
            user_id=user["id"], action=audit_service.ACTION_UNAUTHORIZED,
            ip_address=ip, success=False, resource_id=file_id,
        )
        abort(403)

    record = result
    try:
        ciphertext = file_service.read_encrypted_file(cfg["STORAGE_DIR"], record["stored_filename"])
        plaintext = decrypt_bytes(
            cfg["_ENCRYPTION_KEY_BYTES"], ciphertext, record["nonce_b64"],
            user_id=record["user_id"], stored_filename=record["stored_filename"],
        )
    except (FileValidationError, DecryptionError):
        audit_service.log_action(
            user_id=user["id"], action=audit_service.ACTION_DOWNLOAD,
            ip_address=ip, success=False, resource_id=file_id,
        )
        abort(500)

    audit_service.log_action(
        user_id=user["id"], action=audit_service.ACTION_DOWNLOAD,
        ip_address=ip, success=True, resource_id=file_id,
    )

    return send_file(
        io.BytesIO(plaintext),
        mimetype=record["mime_type"],
        as_attachment=True,
        download_name=record["original_filename"],
    )


@files_bp.route("/delete/<int:file_id>", methods=["POST"])
@auth_service.login_required
def delete(file_id: int):
    user = auth_service.current_user()
    db = get_db()
    cfg = current_app.config
    ip = auth_service.get_client_ip()

    result = _load_owned_file_or_none(db, file_id, user)

    if result is None:
        abort(404)
    if result == "forbidden":
        audit_service.log_action(
            user_id=user["id"], action=audit_service.ACTION_UNAUTHORIZED,
            ip_address=ip, success=False, resource_id=file_id,
        )
        abort(403)

    record = result
    file_service.delete_encrypted_file(cfg["STORAGE_DIR"], record["stored_filename"])
    file_model.delete_file(db, file_id)

    audit_service.log_action(
        user_id=user["id"], action=audit_service.ACTION_DELETE,
        ip_address=ip, success=True, resource_id=file_id,
    )
    flash("File deleted.", "success")
    return redirect(_safe_redirect_target())
