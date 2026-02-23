import re

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from allauth.socialaccount.models import SocialAccount

from .tokens import VersionedRefreshToken
from phonenumber_field.serializerfields import PhoneNumberField as SerializerPhoneNumberField
from phonenumber_field.validators import validate_international_phonenumber, validate_phonenumber

User = get_user_model()


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Uses VersionedRefreshToken so that every token pair issued via
    SimpleJWT's obtain-pair flow carries token_version.
    """

    token_class = VersionedRefreshToken

    @classmethod
    def get_token(cls, user):
        return cls.token_class.for_user(user)


# =============================================================================
# AUTH SERIALIZERS (Used by dj_rest_auth)
# =============================================================================


class AuthUserSerializer(serializers.ModelSerializer):
    """
    Lightweight serializer for authentication responses.
    Used by dj_rest_auth to return user data with JWT tokens.
    """

    full_name = serializers.CharField(read_only=True)
    has_complete_profile = serializers.BooleanField(read_only=True)
    auth_provider = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "first_name",
            "last_name",
            "full_name",
            "avatar",
            "title",
            "has_complete_profile",
            "auth_provider",
        )
        read_only_fields = fields

    def get_auth_provider(self, obj):
        """Return the auth provider for the user (e.g. 'google', 'github', 'email')."""
        try:
            sa = SocialAccount.objects.filter(user=obj).order_by("-pk").first()
            if sa:
                return sa.provider
        except Exception:
            pass
        # Fallback to email/local if no social account exists
        if obj.has_usable_password():
            return "email"
        return "unknown"


# =============================================================================
# REGISTRATION SERIALIZER
# =============================================================================


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration.
    Handles email/password signup with strong validation.
    """

    password = serializers.CharField(
        write_only=True,
        min_length=8,
        style={"input_type": "password"},
        help_text="Min 8 chars, must include uppercase, lowercase, digit, and special char.",
    )
    password_confirm = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
        help_text="Confirm your password.",
    )

    class Meta:
        model = User
        fields = (
            "email",
            "password",
            "password_confirm",
        )

    def validate_email(self, value):
        """Ensure email is unique and properly formatted."""
        email = value.lower().strip()
        if User.objects.filter(email__iexact=email).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return email

    def validate_password(self, value):
        """Strong password validation."""
        errors = []

        if len(value) < 8:
            errors.append("Password must be at least 8 characters long.")
        if not re.search(r"[A-Z]", value):
            errors.append("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", value):
            errors.append("Password must contain at least one lowercase letter.")
        if not re.search(r"\d", value):
            errors.append("Password must contain at least one digit.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", value):
            errors.append("Password must contain at least one special character.")

        # Also run Django's built-in validators
        try:
            validate_password(value)
        except DjangoValidationError as e:
            errors.extend(e.messages)

        if errors:
            raise serializers.ValidationError(errors)

        return value

    def validate(self, attrs):
        """Ensure passwords match."""
        if attrs.get("password") != attrs.get("password_confirm"):
            raise serializers.ValidationError(
                {"password_confirm": "Passwords do not match."}
            )
        return attrs

    def create(self, validated_data):
        """Create user with hashed password."""
        validated_data.pop("password_confirm")
        password = validated_data.pop("password")

        with transaction.atomic():
            user = User(
                email=validated_data["email"],
                username=validated_data["email"],  # Set username = email
            )
            user.set_password(password)
            user.save()

        return user


# =============================================================================
# PROFILE SERIALIZERS
# =============================================================================


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Full profile serializer for authenticated users viewing/editing their own profile.
    """

    full_name = serializers.CharField(read_only=True)
    has_complete_profile = serializers.BooleanField(read_only=True)
    email = serializers.EmailField(read_only=True)  # Email cannot be changed here
    auth_provider = serializers.SerializerMethodField(read_only=True)
    phone_number = SerializerPhoneNumberField(
        required=False, allow_blank=True, help_text="Contact phone number with country code"
    )

    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "first_name",
            "last_name",
            "full_name",
            "avatar",
            "title",
            "bio",
            "location",
            "website",
            "github_url",
            "linkedin_url",
            "twitter_url",
            "years_of_experience",
            "is_available_for_hire",
            "is_open_to_freelance",
            "is_profile_public",
            "has_complete_profile",
            "email_verified",
            "phone_number",
            "date_of_birth",
            "created_at",
            "updated_at",
            "auth_provider",
        )
        read_only_fields = ("id", "email", "created_at", "updated_at")

    def get_auth_provider(self, obj):
        """Return the auth provider for the user (e.g. 'google', 'github', 'email')."""
        try:
            sa = SocialAccount.objects.filter(user=obj).order_by("-pk").first()
            if sa:
                return sa.provider
        except Exception:
            pass
        if obj.has_usable_password():
            return "email"
        return "unknown"

    def validate_website(self, value):
        """Validate website URL format."""
        if value and not value.startswith(("http://", "https://")):
            value = f"https://{value}"
        return value

    def validate_github_url(self, value):
        """Validate GitHub URL."""
        if value and "github.com" not in value.lower():
            raise serializers.ValidationError("Please enter a valid GitHub URL.")
        return value

    def validate_linkedin_url(self, value):
        """Validate LinkedIn URL."""
        if value and "linkedin.com" not in value.lower():
            raise serializers.ValidationError("Please enter a valid LinkedIn URL.")
        return value
    def validate_phone_number(self, value):
        """Validate if phone number is valid and if phone number is in international format."""
        if value:
            try:
                validate_phonenumber(value)
                validate_international_phonenumber(value)
            except serializers.ValidationError as e:
                print(str(e))
                raise serializers.ValidationError(e.detail)
        return value


class PublicUserProfileSerializer(serializers.ModelSerializer):
    """
    Public profile serializer - limited fields for viewing other users' profiles.
    Only shows information the user has made public.
    """

    full_name = serializers.CharField(read_only=True)

    class Meta:
        model = User
        fields = (
            "id",
            "full_name",
            "avatar",
            "title",
            "bio",
            "location",
            "website",
            "github_url",
            "linkedin_url",
            "twitter_url",
            "years_of_experience",
            "is_available_for_hire",
            "is_open_to_freelance",
        )


# =============================================================================
# PASSWORD CHANGE SERIALIZER
# =============================================================================


class ChangePasswordSerializer(serializers.Serializer):
    """Serializer for password change endpoint."""

    current_password = serializers.CharField(
        write_only=True, style={"input_type": "password"}
    )
    new_password = serializers.CharField(
        write_only=True, min_length=8, style={"input_type": "password"}
    )
    new_password_confirm = serializers.CharField(
        write_only=True, style={"input_type": "password"}
    )

    def validate_current_password(self, value):
        """Verify current password is correct."""
        user = self.context["request"].user
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect.")
        return value

    def validate_new_password(self, value):
        """Apply same strong password rules."""
        errors = []

        if len(value) < 8:
            errors.append("Password must be at least 8 characters long.")
        if not re.search(r"[A-Z]", value):
            errors.append("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", value):
            errors.append("Password must contain at least one lowercase letter.")
        if not re.search(r"\d", value):
            errors.append("Password must contain at least one digit.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", value):
            errors.append("Password must contain at least one special character.")

        if errors:
            raise serializers.ValidationError(errors)

        return value

    def validate(self, attrs):
        """Ensure new passwords match and differ from current."""
        if attrs["new_password"] != attrs["new_password_confirm"]:
            raise serializers.ValidationError(
                {"new_password_confirm": "New passwords do not match."}
            )

        if attrs["current_password"] == attrs["new_password"]:
            raise serializers.ValidationError(
                {
                    "new_password": "New password must be different from current password."
                }
            )

        return attrs

    def save(self):
        """Update user's password and revoke all existing tokens."""
        user = self.context["request"].user
        user.set_password(self.validated_data["new_password"])
        # Bump token_version to invalidate every outstanding JWT
        user.token_version += 1
        user.refresh_jti = ""  # Invalidate current refresh token
        user.save(update_fields=["password", "token_version", "refresh_jti"])
        return user


# =============================================================================
# PASSWORD RESET SERIALIZERS
# =============================================================================


class PasswordResetRequestSerializer(serializers.Serializer):
    """Serializer for requesting a password reset email."""

    email = serializers.EmailField()

    def validate_email(self, value):
        """Check if user with this email exists."""
        email = value.lower().strip()
        # We don't reveal if user exists for security
        return email


class PasswordResetConfirmSerializer(serializers.Serializer):
    """Serializer for confirming password reset with token."""

    token = serializers.CharField(write_only=True)
    uid = serializers.CharField(write_only=True)
    new_password = serializers.CharField(
        write_only=True, min_length=8, style={"input_type": "password"}
    )
    new_password_confirm = serializers.CharField(
        write_only=True, style={"input_type": "password"}
    )

    def validate_new_password(self, value):
        """Apply same strong password rules."""
        errors = []

        if len(value) < 8:
            errors.append("Password must be at least 8 characters long.")
        if not re.search(r"[A-Z]", value):
            errors.append("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", value):
            errors.append("Password must contain at least one lowercase letter.")
        if not re.search(r"\d", value):
            errors.append("Password must contain at least one digit.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            errors.append("Password must contain at least one special character.")

        if errors:
            raise serializers.ValidationError(errors)

        return value

    def validate(self, attrs):
        """Ensure new passwords match."""
        if attrs["new_password"] != attrs["new_password_confirm"]:
            raise serializers.ValidationError(
                {"new_password_confirm": "Passwords do not match."}
            )
        return attrs
