from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import serializers

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "email",
            "password",
            "bio",
            "github_url",
            "linkedin_url",
        )
        read_only_fields = (
            "id",
            "username",
        )  # Email and username are set during registration and should not be changed via this serializer
        extra_kwargs = {"password": {"write_only": True}}

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with that email already exists.")
        return value

    def validate(self, attrs):
        password = attrs.get("password")
        if password:
            if len(password) < 8:
                raise serializers.ValidationError(
                    "Password must be at least 8 characters long."
                )
            if not any(char.isdigit() for char in password):
                raise serializers.ValidationError(
                    "Password must contain at least one digit."
                )
            if not any(char.isupper() for char in password):
                raise serializers.ValidationError(
                    "Password must contain at least one uppercase letter."
                )
            if not any(char.islower() for char in password):
                raise serializers.ValidationError(
                    "Password must contain at least one lowercase letter."
                )
            if not any(
                char in ["!", "@", "#", "$", "%", "^", "&", "*"] for char in password
            ):
                raise serializers.ValidationError(
                    "Password must contain at least one special character."
                )

        return super().validate(attrs)

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        validated_data["username"] = validated_data["email"]

        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance
