import datetime as dt
import hashlib
import hmac
import secrets


def _now_iso():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def generate_recovery_codes(count: int):
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(12).upper()
        codes.append(f"{raw[:8]}-{raw[8:16]}-{raw[16:]}")
    return codes


def _hash_code(code: str, salt: bytes):
    normalized = "".join((code or "").upper().split()).replace("-", "")
    digest = hashlib.sha256(salt + normalized.encode("ascii", "ignore")).hexdigest()
    return salt.hex() + ":" + digest


def replace_recovery_codes(db, *, user_id: int, codes: list[str]):
    db.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
    for code in codes:
        salt = secrets.token_bytes(16)
        db.execute(
            "INSERT INTO recovery_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)",
            (user_id, _hash_code(code, salt), _now_iso()),
        )
    db.commit()


def consume_recovery_code(db, *, user_id: int, code: str) -> bool:
    rows = db.execute(
        "SELECT id, code_hash FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
        (user_id,),
    ).fetchall()
    normalized = "".join((code or "").upper().split()).replace("-", "")
    for row in rows:
        try:
            salt_hex, expected = row["code_hash"].split(":", 1)
            salt = bytes.fromhex(salt_hex)
        except (ValueError, TypeError):
            continue
        actual = hashlib.sha256(salt + normalized.encode("ascii", "ignore")).hexdigest()
        if hmac.compare_digest(actual, expected):
            updated = db.execute(
                "UPDATE recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL",
                (_now_iso(), row["id"]),
            )
            db.commit()
            return updated.rowcount == 1
    return False


def count_unused(db, *, user_id: int) -> int:
    row = db.execute(
        "SELECT COUNT(*) AS count FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
        (user_id,),
    ).fetchone()
    return row["count"]


def record_attempt(db, *, user_id: int, ip_address: str, success: bool):
    db.execute(
        "INSERT INTO mfa_attempts (user_id, ip_address, timestamp, success) VALUES (?, ?, ?, ?)",
        (user_id, ip_address, _now_iso(), 1 if success else 0),
    )
    db.commit()


def count_recent_failures(db, *, user_id: int, ip_address: str, since_iso: str) -> int:
    row = db.execute(
        """SELECT COUNT(*) AS count FROM mfa_attempts
           WHERE user_id = ? AND ip_address = ? AND timestamp >= ? AND success = 0""",
        (user_id, ip_address, since_iso),
    ).fetchone()
    return row["count"]