from django.db import models


class User(models.Model):
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=80)
    last_name = models.CharField(max_length=80)
    middle_name = models.CharField(max_length=80, blank=True, default="")

    password_salt = models.CharField(max_length=64)
    password_hash = models.CharField(max_length=64)

    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class AuthSession(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="sessions")
    refresh_jti = models.CharField(max_length=36, unique=True)
    access_jti_last = models.CharField(max_length=36, blank=True, default="")
    is_revoked = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    user_agent = models.CharField(max_length=255, blank=True, default="")
    ip = models.GenericIPAddressField(null=True, blank=True)


class Role(models.Model):
    code = models.CharField(max_length=50, unique=True)
    title = models.CharField(max_length=120)


class Resource(models.Model):
    code = models.CharField(max_length=80, unique=True)


class Action(models.Model):
    code = models.CharField(max_length=80, unique=True)


class Permission(models.Model):
    code = models.CharField(max_length=200, unique=True)  # reports:read
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE)
    action = models.ForeignKey(Action, on_delete=models.CASCADE)


class UserRole(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

    class Meta:
        unique_together = ("user", "role")


class RolePermission(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    class Meta:
        unique_together = ("role", "permission")


class AccessRule(models.Model):
    SUBJECT_ROLE = "role"
    SUBJECT_USER = "user"
    SUBJECT_TYPES = [(SUBJECT_ROLE, "Role"), (SUBJECT_USER, "User")]

    EFFECT_ALLOW = "allow"
    EFFECT_DENY = "deny"
    EFFECTS = [(EFFECT_ALLOW, "Allow"), (EFFECT_DENY, "Deny")]

    subject_type = models.CharField(max_length=10, choices=SUBJECT_TYPES)
    subject_id = models.IntegerField()  # role_id or user_id

    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)
    effect = models.CharField(max_length=10, choices=EFFECTS)
    priority = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)

    class Meta:
        indexes = [
            models.Index(fields=["subject_type", "subject_id"]),
            models.Index(fields=["permission", "effect"]),
        ]
