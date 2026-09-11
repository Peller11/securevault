"""
File-at-rest encryption using AES-256-GCM.

AES-GCM is an AEAD (authenticated encryption with associated data) cipher:
it gives us confidentiality AND integrity/authenticity in one primitive --
if the ciphertext or nonce is tampered with, decryption raises
InvalidTag instead of silently returning corrupted data.

Key management:
  * A single master key (32 bytes / 256 bits) is read from the
    SECUREVAULT_ENCRYPTION_KEY environment variable, base64-encoded.
  * The key is never written to disk, logged, or stored in the database.
  * Each file gets its OWN randomly generated 96-bit (12 byte) nonce.
    Nonces are stored (base64) alongside the file metadata in the
    database -- a nonce is not secret, it just must never be reused with
    the same key, and a fresh os.urandom(12) draw per file makes reuse
    astronomically unlikely.
  * We additionally bind the encryption to the owning user's id and the
    file's stored filename via AEAD "associated data". This means a
    ciphertext blob can't be silently swapped to point at a different
    user's file record without decryption failing.
"""
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

NONCE_LENGTH_BYTES = 12
KEY_LENGTH_BYTES = 32


class EncryptionError(Exception):
    pass


class DecryptionError(Exception):
    pass


def load_master_key(key_b64: str) -> bytes:
    if not key_b64:
        raise EncryptionError(
            "SECUREVAULT_ENCRYPTION_KEY is not set. Generate one with:\n"
            "  python -c \"import os,base64;print(base64.b64encode(os.urandom(32)).decode())\""
        )
    try:
        key = base64.b64decode(key_b64, validate=True)
    except Exception as exc:
        raise EncryptionError("SECUREVAULT_ENCRYPTION_KEY is not valid base64") from exc
    if len(key) != KEY_LENGTH_BYTES:
        raise EncryptionError(
            f"SECUREVAULT_ENCRYPTION_KEY must decode to exactly {KEY_LENGTH_BYTES} bytes "
            f"(got {len(key)}). Use AES-256, not AES-128/192."
        )
    return key


def _associated_data(user_id: int, stored_filename: str) -> bytes:
    return f"{user_id}:{stored_filename}".encode("utf-8")


def encrypt_bytes(master_key: bytes, plaintext: bytes, *, user_id: int, stored_filename: str):
    """Encrypt plaintext, returning (ciphertext_with_tag, nonce_b64)."""
    aesgcm = AESGCM(master_key)
    nonce = os.urandom(NONCE_LENGTH_BYTES)
    aad = _associated_data(user_id, stored_filename)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return ciphertext, base64.b64encode(nonce).decode("ascii")


def decrypt_bytes(master_key: bytes, ciphertext: bytes, nonce_b64: str, *, user_id: int, stored_filename: str) -> bytes:
    """Decrypt ciphertext. Raises DecryptionError if the data or metadata
    binding (user_id / stored_filename) has been tampered with."""
    aesgcm = AESGCM(master_key)
    try:
        nonce = base64.b64decode(nonce_b64)
    except Exception as exc:
        raise DecryptionError("Corrupt nonce") from exc
    aad = _associated_data(user_id, stored_filename)
    try:
        return aesgcm.decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError("Decryption failed: data may be corrupted or tampered with") from exc
