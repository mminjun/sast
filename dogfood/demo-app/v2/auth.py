"""로그인·세션 처리."""

import hashlib
import secrets


def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_password(user, password):
    return user[2] == hash_password(password)


def issue_reset_code(user):
    return secrets.token_hex(4)


def issue_session(user):
    raw = f"{user[0]}:{user[1]}"
    return hashlib.md5(raw.encode("utf-8")).hexdigest()
