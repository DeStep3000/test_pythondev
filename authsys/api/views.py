from datetime import timedelta

from api.serializers import (LoginSerializer, RegisterSerializer,
                             UpdateProfileSerializer)
from authn.jwt import (JwtConfig, decode_and_validate, mint_access_token,
                       mint_refresh_token)
from authn.permissions import HasPermissionCode
from core.models import (AccessRule, Action, AuthSession, Permission, Resource,
                         Role, User)
from django.shortcuts import render
from django.utils import timezone
from django.utils.timezone import now
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView


class RegisterView(APIView):
    authentication_classes = []  # регистрация без токена

    def post(self, request):
        s = RegisterSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        user = s.save()
        return Response({"id": user.id, "email": user.email}, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    authentication_classes = []

    def post(self, request):
        s = LoginSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        user = s.validated_data["user"]

        from django.conf import settings
        cfg = JwtConfig(secret=settings.JWT_SECRET, issuer=settings.JWT_ISSUER)

        refresh_token, refresh_jti = mint_refresh_token(cfg, user.id)
        access_token, access_jti = mint_access_token(cfg, user.id, refresh_jti)

        AuthSession.objects.create(
            user=user,
            refresh_jti=refresh_jti,
            access_jti_last=access_jti,
            is_revoked=False,
            created_at=now(),
            expires_at=now() + timedelta(seconds=cfg.refresh_ttl_sec),
            user_agent=request.headers.get("User-Agent", "")[:255],
        )

        return Response({
            "access_token": access_token,
            "refresh_token": refresh_token,
        })


class RefreshView(APIView):
    authentication_classes = []

    def post(self, request):
        token = request.data.get("refresh_token", "")
        if not token:
            return Response({"detail": "refresh_token required"}, status=400)

        from django.conf import settings
        cfg = JwtConfig(secret=settings.JWT_SECRET, issuer=settings.JWT_ISSUER)

        payload = decode_and_validate(cfg, token)
        if payload.get("type") != "refresh":
            return Response({"detail": "Token type must be refresh"}, status=400)

        user_id = int(payload["sub"])
        refresh_jti = payload["jti"]

        session = AuthSession.objects.filter(refresh_jti=refresh_jti).first()
        if not session or session.is_revoked or session.expires_at <= now():
            return Response({"detail": "Session revoked/expired"}, status=401)

        user = User.objects.filter(id=user_id, is_active=True).first()
        if not user:
            return Response({"detail": "User not found/inactive"}, status=401)

        new_access, access_jti = mint_access_token(cfg, user.id, refresh_jti)
        session.access_jti_last = access_jti
        session.save(update_fields=["access_jti_last"])

        return Response({"access_token": new_access})


class LogoutView(APIView):
    def post(self, request):
        # logout = revoke текущей сессии по sid из access-токена
        payload = getattr(request, "auth", None)  # вернёт JwtAuthentication
        if not payload:
            return Response({"detail": "Unauthorized"}, status=401)

        sid = payload["sid"]
        AuthSession.objects.filter(refresh_jti=sid).update(is_revoked=True)
        return Response(status=204)


class MeView(APIView):
    def get(self, request):
        if not request.user or not request.user.is_active:
            return Response({"detail": "Unauthorized"}, status=401)
        u = request.user
        return Response({
            "id": u.id,
            "email": u.email,
            "first_name": u.first_name,
            "last_name": u.last_name,
            "middle_name": u.middle_name,
            "is_active": u.is_active,
        })

    def patch(self, request):
        if not request.user or not request.user.is_active:
            return Response({"detail": "Unauthorized"}, status=401)

        s = UpdateProfileSerializer(data=request.data, partial=True)
        s.is_valid(raise_exception=True)

        u = request.user
        for k, v in s.validated_data.items():
            setattr(u, k, v)
        u.save()

        return Response({"detail": "updated"})


class SoftDeleteMeView(APIView):
    def post(self, request):
        if not request.user:
            return Response({"detail": "Unauthorized"}, status=401)

        # мягкое удаление + разлогин
        u = request.user
        u.is_active = False
        u.save(update_fields=["is_active"])

        AuthSession.objects.filter(user=u).update(is_revoked=True)
        return Response(status=204)

# ---- Mock business ресурсы ----


class ReportsView(APIView):
    permission_classes = [
        IsAuthenticated,
        HasPermissionCode.with_code("reports:read"),
    ]

    def get(self, request):
        return Response({
            "items": [
                {"id": 1, "title": "Sales report (mock)"},
                {"id": 2, "title": "Costs report (mock)"},
            ]
        })


class DocumentsCreateView(APIView):
    permission_classes = [HasPermissionCode.with_code("documents:create")]

    def post(self, request):
        if not request.user:
            return Response({"detail": "Unauthorized"}, status=401)
        return Response({"detail": "created (mock)"}, status=201)


class RulesView(APIView):
    permission_classes = [HasPermissionCode.with_code("access:manage")]

    def get(self, request):
        # вернуть список правил (упрощённо)
        rules = AccessRule.objects.all().order_by("-priority")[:200]
        data = [{
            "id": r.id,
            "subject_type": r.subject_type,
            "subject_id": r.subject_id,
            "permission": r.permission.code,
            "effect": r.effect,
            "priority": r.priority,
            "is_active": r.is_active,
        } for r in rules]
        return Response({"rules": data})
