from authn.hashing import hash_password, verify_password
from core.models import User
from rest_framework import serializers


class RegisterSerializer(serializers.Serializer):
    last_name = serializers.CharField()
    first_name = serializers.CharField()
    middle_name = serializers.CharField(required=False, allow_blank=True)
    email = serializers.EmailField()
    password = serializers.CharField(min_length=8)
    password_repeat = serializers.CharField(min_length=8)

    def validate(self, attrs):
        if attrs["password"] != attrs["password_repeat"]:
            raise serializers.ValidationError("Passwords do not match")
        if User.objects.filter(email=attrs["email"]).exists():
            raise serializers.ValidationError("Email already registered")
        return attrs

    def create(self, validated_data):
        salt_hex, hash_hex = hash_password(validated_data["password"])
        return User.objects.create(
            email=validated_data["email"],
            first_name=validated_data["first_name"],
            last_name=validated_data["last_name"],
            middle_name=validated_data.get("middle_name", ""),
            password_salt=salt_hex,
            password_hash=hash_hex,
            is_active=True,
        )


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, attrs):
        user = User.objects.filter(email=attrs["email"]).first()
        if not user or not user.is_active:
            raise serializers.ValidationError("Invalid credentials")

        if not verify_password(attrs["password"], user.password_salt, user.password_hash):
            raise serializers.ValidationError("Invalid credentials")

        attrs["user"] = user
        return attrs


class UpdateProfileSerializer(serializers.Serializer):
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)
    middle_name = serializers.CharField(required=False, allow_blank=True)
