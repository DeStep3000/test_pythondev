import time
import uuid
from dataclasses import dataclass

import jwt


@dataclass(frozen=True)
class JwtConfig:
    secret: str
    issuer: str = "authsys"
    access_ttl_sec: int = 15 * 60
    refresh_ttl_sec: int = 7 * 24 * 60 * 60
    alg: str = "HS256"


def _now() -> int:
    return int(time.time())


def mint_access_token(cfg: JwtConfig, user_id: int, session_refresh_jti: str) -> tuple[str, str]:
    """
    access token содержит:
    - sub: user_id
    - jti: уникальный id токена (для отладки/ротации можно хранить)
    - sid: refresh_jti сессии (связываем access с конкретной refresh-сессией)
    """
    jti = str(uuid.uuid4())
    payload = {
        "iss": cfg.issuer,
        "sub": str(user_id),
        "type": "access",
        "jti": jti,
        "sid": session_refresh_jti,
        "iat": _now(),
        "exp": _now() + cfg.access_ttl_sec,
    }
    token = jwt.encode(payload, cfg.secret, algorithm=cfg.alg)
    return token, jti


def mint_refresh_token(cfg: JwtConfig, user_id: int) -> tuple[str, str]:
    refresh_jti = str(uuid.uuid4())
    payload = {
        "iss": cfg.issuer,
        "sub": str(user_id),
        "type": "refresh",
        "jti": refresh_jti,
        "iat": _now(),
        "exp": _now() + cfg.refresh_ttl_sec,
    }
    token = jwt.encode(payload, cfg.secret, algorithm=cfg.alg)
    return token, refresh_jti


def decode_and_validate(cfg: JwtConfig, token: str) -> dict:
    """
    Базовая проверка подписи, exp, iss.
    """
    return jwt.decode(
        token,
        cfg.secret,
        algorithms=[cfg.alg],
        issuer=cfg.issuer,
        options={"require": ["exp", "iat", "iss", "sub", "type", "jti"]},
    )
