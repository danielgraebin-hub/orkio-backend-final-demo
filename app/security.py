from __future__ import annotations

import os
import time
import base64
import hashlib
import hmac
from typing import Any, Dict

import jwt

JWT_ALG = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRES_IN = int(os.getenv("JWT_EXPIRES_IN", "3600"))
PBKDF2_ITERS = int(os.getenv("PBKDF2_ITERS", "600000"))


def _clean_env(v: str | None) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    # Railway UI sometimes stores values with surrounding quotes; strip them.
    if (len(s) >= 2) and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        s = s[1:-1].strip()
    return s


def jwt_secret() -> str | None:
    return _clean_env(os.getenv("JWT_SECRET"))


def require_secret() -> None:
    s = jwt_secret()
    if not s or s.lower().startswith("change"):
        raise RuntimeError("JWT_SECRET is not configured (refuse to start)")


def new_salt(nbytes: int = 16) -> str:
    return base64.b64encode(os.urandom(nbytes)).decode("utf-8")


def pbkdf2_hash(password: str, salt: str) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERS)
    return base64.b64encode(dk).decode("utf-8")


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    actual = pbkdf2_hash(password, salt)
    return hmac.compare_digest(actual, expected_hash)


def mint_token(payload: Dict[str, Any]) -> str:
    require_secret()
    s = jwt_secret()
    now = int(time.time())
    exp = now + JWT_EXPIRES_IN
    to_encode = dict(payload)
    to_encode.update({"iat": now, "exp": exp})
    return jwt.encode(to_encode, s, algorithm=JWT_ALG)


def decode_token(token: str) -> Dict[str, Any]:
    require_secret()
    s = jwt_secret()
    return jwt.decode(token, s, algorithms=[JWT_ALG])
