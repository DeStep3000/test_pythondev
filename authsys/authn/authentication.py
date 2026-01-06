from authn.jwt import JwtConfig, decode_and_validate
from core.models import AuthSession, User
from django.utils.timezone import now
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed


class JwtAuthentication(BaseAuthentication):
    """
    Идентификация пользователя через access JWT.
    ВАЖНО: дополнительно проверяем, что сессия (refresh_jti) не revoked.
    """

    def __init__(self):
        from django.conf import settings
        self.cfg = JwtConfig(secret=settings.JWT_SECRET,
                             issuer=settings.JWT_ISSUER)

    def authenticate(self, request):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None  # DRF дальше сам решит, что юзер anonymous

        token = header.removeprefix("Bearer ").strip()
        try:
            payload = decode_and_validate(self.cfg, token)
        except Exception as e:
            raise AuthenticationFailed(f"Invalid token: {e}")

        if payload.get("type") != "access":
            raise AuthenticationFailed("Token type must be access")

        user_id = int(payload["sub"])
        sid = payload["sid"]  # refresh_jti сессии

        user = User.objects.filter(id=user_id).first()
        if not user or not user.is_active:
            raise AuthenticationFailed("User not found or inactive")

        session = AuthSession.objects.filter(refresh_jti=sid).first()
        if not session or session.is_revoked:
            raise AuthenticationFailed("Session revoked")

        if session.expires_at <= now():
            raise AuthenticationFailed("Session expired")

        session.access_jti_last = payload["jti"]
        session.save(update_fields=["access_jti_last"])

        return (user, payload)
