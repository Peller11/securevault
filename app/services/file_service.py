"""
File upload validation and secure storage.

Key defensive measures implemented here:

  1. Extension allow-listing: only extensions in Config.ALLOWED_EXTENSIONS
     are accepted, checked against a lower-cased, sanitized copy of the
     filename's suffix.

  2. Content-based MIME sniffing: we don't trust the browser-supplied
     Content-Type header. Instead we inspect the first bytes of the
     uploaded content ("magic numbers") against a small signature table
     and cross-check that the sniffed type is consistent with the claimed
     extension. This is the same technique python-magic/libmagic uses
     under the hood, implemented directly against the stdlib so the
     project has no extra runtime dependencies beyond Flask and
     `cryptography`.

  3. Size enforcement: Flask's MAX_CONTENT_LENGTH rejects oversized
     request bodies at the framework level (413) before the view even
     runs; we additionally re-check the actual byte length we read.

  4. Random server-side filenames: we NEVER use the client-supplied
     filename to build a filesystem path. A fresh `secrets.token_hex(32)`
     name is generated for every upload. The original filename is stored
     in the database purely as a *display* label (and is HTML-escaped by
     Jinja2 autoescaping when rendered) -- it never touches the
     filesystem.

  5. Storage outside the web root: files are written under
     Config.STORAGE_DIR, which is not registered as a Flask static
     folder and has no route serving it directly. The only way to read a
     file back out is through the authenticated download endpoint, which
     enforces ownership and decrypts server-side.

  6. Path traversal guard: even though we generate filenames ourselves,
     `resolve_storage_path` double-checks that the resulting path is
     still inside STORAGE_DIR before any read/write, using `Path.resolve()`
     and `is_relative_to()`. This protects against any future code change
     that might accidentally pass a less-trusted value in.
"""
import os
import secrets
from pathlib import Path

# (extension, expected_mime) -> signature checker
_SIGNATURES = [
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"PK\x03\x04", "application/zip"),  # also covers .docx (zip container)
]

_EXTENSION_MIME_HINTS = {
    "pdf": "application/pdf",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "zip": "application/zip",
    "docx": "application/zip",  # docx is a zip container
    "txt": "text/plain",
    "csv": "text/plain",
}


class FileValidationError(Exception):
    pass


def sniff_mime_type(content: bytes) -> str | None:
    for signature, mime in _SIGNATURES:
        if content.startswith(signature):
            return mime
    # Heuristic for plain text: printable/whitespace bytes only, sampled.
    sample = content[:2048]
    if sample and all((32 <= b <= 126) or b in (9, 10, 13) for b in sample):
        return "text/plain"
    return None


def get_extension(filename: str) -> str:
    return Path(filename).suffix.lower().lstrip(".")


def validate_upload(filename: str, content: bytes, *, allowed_extensions: set, max_size_bytes: int) -> str:
    """Validate an uploaded file. Returns the confirmed MIME type, or
    raises FileValidationError with a user-safe message."""
    if not filename or filename.strip() == "":
        raise FileValidationError("A filename is required.")

    if len(content) == 0:
        raise FileValidationError("Uploaded file is empty.")

    if len(content) > max_size_bytes:
        raise FileValidationError(
            f"File exceeds the maximum allowed size of {max_size_bytes // (1024 * 1024)}MB."
        )

    ext = get_extension(filename)
    if ext not in allowed_extensions:
        raise FileValidationError(f"File type '.{ext}' is not permitted.")

    sniffed = sniff_mime_type(content)
    if sniffed is None:
        # Plain-text files with unusual leading bytes, e.g. csv with a BOM,
        # can legitimately fail the printable-ASCII heuristic; only text-like
        # extensions get a pass here, everything else must match a known
        # binary signature.
        if ext not in ("txt", "csv"):
            raise FileValidationError(
                "File content does not match a recognized, permitted file type."
            )
        sniffed = "text/plain"

    expected_hint = _EXTENSION_MIME_HINTS.get(ext)
    if expected_hint and sniffed != expected_hint:
        raise FileValidationError(
            "File content does not match its extension (possible spoofed file type)."
        )

    return sniffed


def generate_stored_filename() -> str:
    return secrets.token_hex(32)


def resolve_storage_path(storage_dir: str, stored_filename: str) -> Path:
    """Build and validate the on-disk path for a stored (encrypted) file.

    Defends against path traversal: even though `stored_filename` is
    always server-generated (a hex token, never derived from user input),
    we still verify the final resolved path is inside STORAGE_DIR before
    returning it.
    """
    base = Path(storage_dir).resolve()
    base.mkdir(parents=True, exist_ok=True)
    candidate = (base / stored_filename).resolve()
    if not str(candidate).startswith(str(base) + os.sep) and candidate != base:
        raise FileValidationError("Invalid storage path.")
    if candidate.parent != base:
        raise FileValidationError("Invalid storage path.")
    return candidate


def write_encrypted_file(storage_dir: str, stored_filename: str, ciphertext: bytes) -> None:
    path = resolve_storage_path(storage_dir, stored_filename)
    # Write privately: owner read/write only.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(ciphertext)
    except Exception:
        if path.exists():
            path.unlink(missing_ok=True)
        raise


def read_encrypted_file(storage_dir: str, stored_filename: str) -> bytes:
    path = resolve_storage_path(storage_dir, stored_filename)
    if not path.exists():
        raise FileValidationError("Stored file is missing.")
    with open(path, "rb") as f:
        return f.read()


def delete_encrypted_file(storage_dir: str, stored_filename: str) -> None:
    path = resolve_storage_path(storage_dir, stored_filename)
    if path.exists():
        path.unlink()
