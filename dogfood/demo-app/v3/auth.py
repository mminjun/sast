"""로그인·세션 처리."""

import hashlib
import os
import secrets

HASH_ITERATIONS = 120_000


def hash_password(password, salt=None):
    salt = salt if salt is not None else os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, HASH_ITERATIONS)
    return salt.hex() + ":" + digest.hex()


def verify_password(user, password):
    stored = user[2]
    salt_hex, _, _ = stored.partition(":")
    return stored == hash_password(password, bytes.fromhex(salt_hex))


def issue_reset_code(user):
    return secrets.token_hex(4)


def issue_session(user):
    raw = f"{user[0]}:{user[1]}"
    return hashlib.md5(raw.encode("utf-8")).hexdigest()
