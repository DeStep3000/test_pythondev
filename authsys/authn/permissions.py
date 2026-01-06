from core.models import AccessRule, Permission, RolePermission, UserRole
from rest_framework.permissions import BasePermission


class HasPermissionCode(BasePermission):
    """
    Использование: permission_classes = [HasPermissionCode.with_code("reports:read")]
    """

    required_code: str | None = None

    @classmethod
    def with_code(cls, code: str):
        class _P(cls):
            required_code = code
        return _P

    def has_permission(self, request, view):
        if not request.user or not getattr(request.user, "id", None):
            return False  # DRF вернёт 401 если IsAuthenticated, но мы работаем явно в views

        code = self.required_code
        if not code:
            return True

        perm = Permission.objects.filter(code=code).first()
        if not perm:
            return False

        user_id = request.user.id

        # 1) Собираем роли пользователя
        role_ids = list(UserRole.objects.filter(
            user_id=user_id).values_list("role_id", flat=True))

        # 2) Правила (deny/allow) - сначала user rules, потом role rules, сортировка по priority desc
        rules = list(
            AccessRule.objects.filter(is_active=True, permission=perm).filter(
                # либо rule на user, либо на его роли
                # (subject_type, subject_id) in ...
            )
        )

        filtered = []
        for r in rules:
            if r.subject_type == AccessRule.SUBJECT_USER and r.subject_id == user_id:
                filtered.append(r)
            if r.subject_type == AccessRule.SUBJECT_ROLE and r.subject_id in role_ids:
                filtered.append(r)

        filtered.sort(key=lambda r: r.priority, reverse=True)

        for r in filtered:
            if r.effect == AccessRule.EFFECT_DENY:
                return False
            if r.effect == AccessRule.EFFECT_ALLOW:
                return True

        # 3) Если явных правил нет - fallback на role_permissions
        role_perm_exists = RolePermission.objects.filter(
            role_id__in=role_ids, permission=perm).exists()
        return role_perm_exists
