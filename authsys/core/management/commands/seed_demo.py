from datetime import timedelta

from authn.hashing import hash_password
from core.models import (AccessRule, Action, Permission, Resource, Role,
                         RolePermission, User, UserRole)
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils.timezone import now


class Command(BaseCommand):
    help = "Seed demo data for RBAC + policies"

    @transaction.atomic
    def handle(self, *args, **options):
        self.stdout.write(self.style.WARNING("Seeding demo data..."))

        # --- 1) Resources ---
        resources = {}
        for code in ["reports", "documents", "access"]:
            obj, _ = Resource.objects.get_or_create(code=code)
            resources[code] = obj

        # --- 2) Actions ---
        actions = {}
        for code in ["read", "create", "update", "delete", "manage"]:
            obj, _ = Action.objects.get_or_create(code=code)
            actions[code] = obj

        # --- 3) Permissions ---
        perm_specs = [
            ("reports:read", "reports", "read"),
            ("documents:create", "documents", "create"),
            ("documents:read", "documents", "read"),
            ("access:manage", "access", "manage"),
        ]

        perms = {}
        for code, r_code, a_code in perm_specs:
            obj, _ = Permission.objects.get_or_create(
                code=code,
                defaults={
                    "resource": resources[r_code],
                    "action": actions[a_code],
                },
            )
            # если permission уже был, гарантируем связки resource/action (на случай правок)
            if obj.resource_id != resources[r_code].id or obj.action_id != actions[a_code].id:
                obj.resource = resources[r_code]
                obj.action = actions[a_code]
                obj.save(update_fields=["resource", "action"])
            perms[code] = obj

        # --- 4) Roles ---
        admin_role, _ = Role.objects.get_or_create(
            code="admin", defaults={"title": "Administrator"})
        user_role, _ = Role.objects.get_or_create(
            code="user", defaults={"title": "User"})

        # --- 5) Role permissions ---
        # admin получает всё
        for p in perms.values():
            RolePermission.objects.get_or_create(role=admin_role, permission=p)

        # user получает минимум: только чтение отчетов
        RolePermission.objects.get_or_create(
            role=user_role, permission=perms["reports:read"])

        # --- 6) Users ---
        def upsert_user(email: str, password: str, first_name: str, last_name: str, middle_name: str = "") -> User:
            u = User.objects.filter(email=email).first()
            salt_hex, hash_hex = hash_password(password)
            if u:
                u.first_name = first_name
                u.last_name = last_name
                u.middle_name = middle_name
                u.password_salt = salt_hex
                u.password_hash = hash_hex
                u.is_active = True
                u.save()
                return u
            return User.objects.create(
                email=email,
                first_name=first_name,
                last_name=last_name,
                middle_name=middle_name,
                password_salt=salt_hex,
                password_hash=hash_hex,
                is_active=True,
            )

        admin = upsert_user("admin@example.com",
                            "Admin12345!", "Admin", "Root")
        user = upsert_user("user@example.com", "User12345!", "Ivan", "Petrov")

        UserRole.objects.get_or_create(user=admin, role=admin_role)
        UserRole.objects.get_or_create(user=user, role=user_role)

        # --- 7) Policies demo (AccessRule) ---
        # Пример: user_role разрешаем reports:read явно (хотя оно и так есть через RolePermission)
        AccessRule.objects.get_or_create(
            subject_type=AccessRule.SUBJECT_ROLE,
            subject_id=user_role.id,
            permission=perms["reports:read"],
            defaults={"effect": AccessRule.EFFECT_ALLOW,
                      "priority": 10, "is_active": True},
        )

        # Пример: запретим конкретному user создавать документы (deny сильнее allow)
        AccessRule.objects.get_or_create(
            subject_type=AccessRule.SUBJECT_USER,
            subject_id=user.id,
            permission=perms["documents:create"],
            defaults={"effect": AccessRule.EFFECT_DENY,
                      "priority": 100, "is_active": True},
        )

        self.stdout.write(self.style.SUCCESS("Seed done ✅"))
        self.stdout.write("Demo users:")
        self.stdout.write("  admin@example.com / Admin12345!")
        self.stdout.write("  user@example.com  / User12345!")
