"""
Password hashing using Argon2id (the OWASP-recommended variant of Argon2).

We use `cryptography.hazmat.primitives.kdf.argon2.Argon2id`, which is a
memory-hard KDF -- passwords are NEVER stored in plaintext and are never
hashed with a fast general-purpose hash like plain SHA-256/MD5. The
`derive_phc_encoded` helper produces a self-describing PHC string
(e.g. "$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>") that embeds the
salt and cost parameters, so verification doesn't need them supplied
separately and cost parameters can be tuned over time without breaking
old hashes.
"""
import os

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidKey

DERIVED_KEY_LENGTH = 32
SALT_LENGTH = 16


def hash_password(plain_password: str, *, time_cost: int, memory_cost_kib: int, parallelism: int) -> str:
    """Return a PHC-encoded Argon2id hash of the given password."""
    if not plain_password:
        raise ValueError("Password must not be empty")
    salt = os.urandom(SALT_LENGTH)
    kdf = Argon2id(
        salt=salt,
        length=DERIVED_KEY_LENGTH,
        iterations=time_cost,
        lanes=parallelism,
        memory_cost=memory_cost_kib,
    )
    return kdf.derive_phc_encoded(plain_password.encode("utf-8"))


def verify_password(plain_password: str, phc_hash: str) -> bool:
    """Constant-time-safe verification of a password against a PHC hash.

    Returns False on any mismatch or malformed hash, rather than raising,
    so calling code has a single simple boolean check.
    """
    if not plain_password or not phc_hash:
        return False
    try:
        Argon2id.verify_phc_encoded(plain_password.encode("utf-8"), phc_hash)
        return True
    except InvalidKey:
        return False
    except Exception:
        # Malformed hash, unsupported params, etc. -- fail closed.
        return False
