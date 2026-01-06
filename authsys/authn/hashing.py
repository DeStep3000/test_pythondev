import hashlib
import os
import hmac

PBKDF2_ITERATIONS = 210_000

def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    """
    Возвращает (salt_hex, hash_hex).
    """
    if salt is None:
        salt = os.urandom(16)

    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )
    return salt.hex(), dk.hex()

def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    _, new_hash_hex = hash_password(password, salt=salt)
    return hmac.compare_digest(new_hash_hex, hash_hex)
