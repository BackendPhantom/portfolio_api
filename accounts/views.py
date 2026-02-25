import logging
import secrets
import uuid
from urllib.parse import urlencode

import requests
from allauth.socialaccount.providers.github.views import GitHubOAuth2Adapter
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.views import SocialLoginView
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core.cache import cache
from django.http import HttpResponseRedirect
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
    inline_serializer,
)
from rest_framework import serializers as drf_serializers
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.exceptions import MethodNotAllowed, NotFound
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError

from commons.permissions import IsSelf

from .models import APIKey
from .serializers import (
    AuthUserSerializer,
    ChangePasswordSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    PublicUserProfileSerializer,
    UserProfileSerializer,
    UserRegistrationSerializer,
)
from .tasks import send_password_reset_email, send_verification_email
from .throttles import (
    LoginRateThrottle,
    PasswordResetRateThrottle,
    SignupRateThrottle,
    SocialExchangeRateThrottle,
)
from .tokens import VersionedRefreshToken, get_tokens_for_user

logger = logging.getLogger(__name__)
User = get_user_model()


# =============================================================================
# AUTHENTICATION VIEWS
# =============================================================================
# class CustomTokenObtainPairView(TokenObtainPairView):
#     serializer_class = CustomTokenObtainPairSerializer


@extend_schema(
    tags=["Authentication"],
    summary="User Registration",
    description="Register a new user with email and password. Sends a verification email that must be confirmed before login.",
    request=UserRegistrationSerializer,
    responses={
        201: inline_serializer(
            name="SignupSuccessResponse",
            fields={
                "message": drf_serializers.CharField(),
                "email": drf_serializers.EmailField(),
            },
        ),
        400: OpenApiResponse(
            description="Validation error - invalid email, weak password, or passwords don't match"
        ),
    },
)
class SignupViewset(GenericAPIView):
    """
    User registration with email and password.
    Requires email verification before account becomes active.
    """

    permission_classes = [AllowAny]
    throttle_classes = [SignupRateThrottle]
    serializer_class = UserRegistrationSerializer

    def post(self, request):
        """
        User registration with email and password.

        POST /api/v1/auth/signup/
        {
            "email": "user@example.com",
            "password": "SecurePass123!",
            "password_confirm": "SecurePass123!",
            "first_name": "John",  // optional
            "last_name": "Doe"     // optional
        }

        Returns success message. User must verify email before logging in.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Mark user as inactive until email is verified
        user.is_active = False
        user.save()

        # Generate verification token
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        # Build verification URL (frontend should handle this route)
        verify_url = f"{settings.FRONTEND_URL}/verify-email?uid={uid}&token={token}"

        # Send verification email
        send_verification_email.delay(user.email, verify_url)

        return Response(
            {
                "message": "Account created successfully. Please check your email to verify your account.",
                "email": user.email,
            },
            status=status.HTTP_201_CREATED,
        )


@extend_schema(
    tags=["Authentication"],
    summary="User Login",
    description="Authenticate user with email and password. Returns JWT access and refresh tokens along with user data.",
    request=inline_serializer(
        name="LoginRequest",
        fields={
            "email": drf_serializers.EmailField(help_text="User's email address"),
            "password": drf_serializers.CharField(help_text="User's password"),
        },
    ),
    responses={
        200: inline_serializer(
            name="LoginSuccessResponse",
            fields={
                "access": drf_serializers.CharField(help_text="JWT access token"),
                "refresh": drf_serializers.CharField(help_text="JWT refresh token"),
                "user": AuthUserSerializer(),
            },
        ),
        400: OpenApiResponse(description="Email and password are required"),
        401: OpenApiResponse(description="Invalid credentials or inactive account"),
    },
)
class LoginView(APIView):
    """
    User login with email and password.

    POST /api/v1/auth/login/
    {
        "email": "user@example.com",
        "password": "SecurePass123!"
    }

    Returns JWT tokens and user data on success.
    """

    permission_classes = [AllowAny]
    throttle_classes = [LoginRateThrottle]

    def post(self, request):
        email = request.data.get("email", "").lower().strip()
        password = request.data.get("password", "")

        if not email or not password:
            return Response(
                {"error": "Email and password are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            return Response(
                {"error": "Invalid email or password."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if not user.check_password(password):
            return Response(
                {"error": "Invalid email or password."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if not user.is_active:
            return Response(
                {"error": "This account has been deactivated."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Generate JWT tokens via the single centralized path
        tokens = get_tokens_for_user(user)

        response_data = {
            **tokens,
            "user": AuthUserSerializer(user).data,
        }

        return Response(response_data, status=status.HTTP_200_OK)


@extend_schema(
    tags=["Authentication"],
    summary="User Logout",
    description="Invalidate all tokens for the authenticated user by incrementing their token version. Logs out from all devices.",
    request=None,
    responses={
        200: inline_serializer(
            name="LogoutSuccessResponse",
            fields={
                "message": drf_serializers.CharField(),
            },
        ),
        401: OpenApiResponse(
            description="Authentication credentials were not provided"
        ),
    },
)
class LogoutView(APIView):
    """Logout user and invalidate all tokens."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        user.token_version += 1
        user.refresh_jti = ""  # Invalidate the current refresh token
        user.save(update_fields=["token_version", "refresh_jti"])

        # Optionally blacklist the refresh token if provided
        refresh_token = request.data.get("refresh")
        if refresh_token:
            try:
                from rest_framework_simplejwt.tokens import RefreshToken

                token = RefreshToken(refresh_token)
                token.blacklist()
            except (TokenError, Exception):
                pass  # Token already blacklisted or invalid — still log out

        # Note: API keys are NOT revoked on logout — they are long-lived
        # and managed separately via /api/v1/auth/api-keys/.

        return Response(
            {"message": "Logged out successfully."},
            status=200,
        )


@extend_schema(
    tags=["Authentication"],
    summary="Refresh Access Token",
    description=(
        "Exchange a valid refresh token for a new access/refresh token pair. "
        "The refresh token must carry a valid `token_version` claim matching "
        "the user's current version, otherwise it is rejected. This prevents "
        "revoked refresh tokens (post-logout / password-change) from minting "
        "new access tokens."
    ),
    request=inline_serializer(
        name="TokenRefreshRequest",
        fields={
            "refresh": drf_serializers.CharField(help_text="Refresh token"),
        },
    ),
    responses={
        200: inline_serializer(
            name="TokenRefreshResponse",
            fields={
                "access": drf_serializers.CharField(help_text="New JWT access token"),
                "refresh": drf_serializers.CharField(help_text="New JWT refresh token"),
            },
        ),
        401: OpenApiResponse(description="Token is invalid or revoked"),
    },
)
class VersionedTokenRefreshView(APIView):
    """
    Custom refresh view that validates both `token_version` and the
    refresh token's JTI against the value stored on the User model.

    This makes every refresh token single-use without a blacklist table:
    - On issuance, the refresh JTI hash is saved to `user.refresh_jti`.
    - On refresh, we verify the incoming JTI matches the stored hash.
    - `get_tokens_for_user` then overwrites the hash with the new JTI,
      so the old token can never be replayed.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        raw_refresh = request.data.get("refresh")
        if not raw_refresh:
            return Response(
                {"error": "Refresh token is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            refresh = VersionedRefreshToken(raw_refresh)
        except TokenError:
            return Response(
                {"error": "Token is invalid or expired."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Extract claims
        token_version = refresh.get("token_version")
        user_id = refresh.get(settings.SIMPLE_JWT.get("USER_ID_CLAIM", "user_id"))
        jti = refresh.get("jti")

        if token_version is None or user_id is None or jti is None:
            return Response(
                {"error": "Malformed token."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # 1. Validate token_version (catches post-logout / password-change)
        if token_version != user.token_version:
            logger.info(
                "Revoked refresh token used for user %s (token v%s != current v%s)",
                user.pk,
                token_version,
                user.token_version,
            )
            return Response(
                {"error": "Token has been revoked."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # 2. Validate JTI (ensures single-use without a blacklist table)
        from .tokens import _hash_jti

        if not user.refresh_jti or _hash_jti(jti) != user.refresh_jti:
            logger.warning(
                "Refresh token replay attempt for user %s (jti mismatch)",
                user.pk,
            )
            # A JTI mismatch after version check passes means the token
            # was already rotated — possible token theft.  Revoke the
            # entire family by bumping token_version.
            user.token_version += 1
            user.refresh_jti = ""
            user.save(update_fields=["token_version", "refresh_jti"])
            return Response(
                {
                    "error": "Token has already been used. All sessions revoked for security."
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Issue a fresh pair — this overwrites refresh_jti on the user
        tokens = get_tokens_for_user(user)
        return Response(tokens, status=status.HTTP_200_OK)


# =============================================================================
# PROFILE VIEWS
# =============================================================================
@extend_schema_view(
    retrieve=extend_schema(
        tags=["User Profile"],
        summary="Get User Profile",
        description="Retrieve the full profile of a specific user. Requires ownership.",
        responses={
            200: UserProfileSerializer,
            404: OpenApiResponse(description="User not found"),
        },
    ),
    update=extend_schema(
        tags=["User Profile"],
        summary="Update User Profile",
        description="Fully update the authenticated user's profile.",
        request=UserProfileSerializer,
        responses={
            200: UserProfileSerializer,
            400: OpenApiResponse(description="Validation error"),
            404: OpenApiResponse(description="User not found"),
        },
    ),
    partial_update=extend_schema(
        tags=["User Profile"],
        summary="Partial Update User Profile",
        description="Partially update the authenticated user's profile.",
        request=UserProfileSerializer,
        responses={
            200: UserProfileSerializer,
            400: OpenApiResponse(description="Validation error"),
            404: OpenApiResponse(description="User not found"),
        },
    ),
    destroy=extend_schema(
        tags=["User Profile"],
        summary="Deactivate User Account",
        description="Deactivate the user's account. Requires password confirmation.",
        request=inline_serializer(
            name="DeactivateAccountRequest",
            fields={
                "password": drf_serializers.CharField(
                    help_text="Current password for confirmation"
                ),
            },
        ),
        responses={
            200: inline_serializer(
                name="DeactivateSuccessResponse",
                fields={"message": drf_serializers.CharField()},
            ),
            400: OpenApiResponse(description="Password is required"),
            401: OpenApiResponse(description="Incorrect password"),
            404: OpenApiResponse(description="User not found"),
        },
    ),
    list=extend_schema(exclude=True),
    create=extend_schema(exclude=True),
)
class UserProfileViewset(viewsets.ModelViewSet):
    """
    Viewset for retrieving and updating user profiles.
    """

    queryset = User.objects.all()

    permission_classes = [IsSelf]

    # def get_object(self):
    #     return self.request.user

    def get_serializer_class(self):
        if self.action == "change_password":
            return ChangePasswordSerializer
        elif self.action == "public_profile":
            return PublicUserProfileSerializer
        elif self.action == "request_password_reset":
            return PasswordResetRequestSerializer
        elif self.action == "confirm_password_reset":
            return PasswordResetConfirmSerializer
        elif self.action == "verify_email":
            return None  # No serializer needed, uses request data directly
        return UserProfileSerializer

    def list(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)

    def create(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)

    @extend_schema(
        tags=["User Profile"],
        summary="Get Current User Profile",
        description="Retrieve the authenticated user's own profile.",
        responses={200: UserProfileSerializer},
    )
    @action(
        detail=False,
        methods=["GET"],
        permission_classes=[IsAuthenticated],
        url_path="me",
    )
    def me(self, request):
        """Get the currently authenticated user's profile. GET /api/v1/users/me/"""
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data)

    @extend_schema(
        tags=["User Profile"],
        summary="Update Current User Profile",
        description="Update the authenticated user's profile (partial update).",
        request=UserProfileSerializer,
        responses={
            200: UserProfileSerializer,
            400: OpenApiResponse(description="Validation error"),
        },
    )
    @action(
        detail=False,
        methods=["PATCH", "PUT"],
        permission_classes=[IsAuthenticated],
        url_path="update-profile",
    )
    def update_profile(self, request):
        """Update the currently authenticated user's profile. PATCH /api/v1/users/update-profile/"""
        partial = request.method == "PATCH"
        serializer = UserProfileSerializer(
            request.user, data=request.data, partial=partial
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs):
        try:
            user = self.get_object()
        except User.DoesNotExist:
            raise NotFound("User Not Found")

        serializer = self.get_serializer(user)
        return Response(serializer.data)

    def update(self, request, *args, **kwargs):
        try:
            user = self.get_object()
        except User.DoesNotExist:
            raise NotFound("User Not Found")

        partial = kwargs.pop("partial", False)
        serializer = self.get_serializer(user, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        try:
            user = self.get_object()
        except User.DoesNotExist:
            raise NotFound("User Not Found")
        password = request.data.get("password")
        if not password:
            return Response(
                {"error": "Password is required to delete account."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not request.user.check_password(password):
            return Response(
                {"error": "Incorrect password."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        user.is_active = False
        user.save()
        return Response(
            {"message": "Account has been deactivated."},
            status=status.HTTP_200_OK,
        )

    @extend_schema(
        tags=["User Profile"],
        summary="Change Password",
        description="Change the authenticated user's password. Requires current password verification.",
        request=ChangePasswordSerializer,
        responses={
            200: inline_serializer(
                name="ChangePasswordSuccessResponse",
                fields={"message": drf_serializers.CharField()},
            ),
            400: OpenApiResponse(
                description="Validation error - current password incorrect or new passwords don't match"
            ),
            404: OpenApiResponse(description="User not found"),
        },
    )
    @action(
        detail=True,
        methods=["PUT", "PATCH"],
        permission_classes=[IsSelf],
        url_path="change-password",
    )
    def change_password(self, request, pk=None):
        """
        Change the authenticated user's password.
        PUT /api/v1/users/{user_id}/change-password/
        PATCH /api/v1/users/{user_id}/change-password/
        {
            "current_password": "OldPassword123!",
            "new_password": "NewPassword456!",
            "new_password_confirm": "NewPassword456!"
        }
        """

        try:
            user = self.get_object()
        except User.DoesNotExist:
            return Response(
                {"error": "User not found."}, status=status.HTTP_404_NOT_FOUND
            )
        serializer = self.get_serializer(
            user, data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)

        serializer.save()
        return Response(
            {"message": "Password changed successfully."}, status=status.HTTP_200_OK
        )

    @extend_schema(
        tags=["User Profile"],
        summary="Get Public Profile",
        description="Retrieve a user's public profile. Only accessible if the user has enabled public profile visibility.",
        responses={
            200: PublicUserProfileSerializer,
            403: OpenApiResponse(description="This profile is private"),
            404: OpenApiResponse(description="User not found"),
        },
    )
    @action(
        detail=True, methods=["get"], permission_classes=[AllowAny], url_path="public"
    )
    def public_profile(self, request, pk=None):
        """
        Get a user's public profile by ID.

        GET /api/v1/users/{user_id}/public/
        Returns public profile info (limited fields).
        """
        try:
            user = self.get_object()
        except User.DoesNotExist:
            return Response(
                {"error": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Check if profile is public
        if not user.is_profile_public:
            return Response(
                {"error": "This profile is private."},
                status=status.HTTP_403_FORBIDDEN,
            )

        serializer = self.get_serializer(user)
        return Response(serializer.data)

    @extend_schema(
        tags=["Password Management"],
        summary="Request Password Reset",
        description="Request a password reset email. Always returns success to prevent email enumeration attacks.",
        request=PasswordResetRequestSerializer,
        responses={
            200: inline_serializer(
                name="PasswordResetRequestResponse",
                fields={"message": drf_serializers.CharField()},
            ),
        },
    )
    @action(
        detail=False,
        methods=["POST"],
        permission_classes=[AllowAny],
        throttle_classes=[PasswordResetRateThrottle],
        url_path="password-reset",
    )
    def request_password_reset(self, request):
        """
        Request a password reset email.

        POST /api/v1/users/password-reset/
        {
            "email": "user@example.com"
        }

        Always returns success to prevent email enumeration attacks.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]

        try:
            user = User.objects.get(email__iexact=email, is_active=True)
            # Generate token and uid
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            # Build reset URL (frontend should handle this route)
            reset_url = (
                f"{settings.FRONTEND_URL}/reset-password?uid={uid}&token={token}"
            )

            # Send email
            send_password_reset_email.delay(user.email, reset_url)
        except User.DoesNotExist:
            # Don't reveal that the user doesn't exist
            pass
        except Exception:
            # Log the error but don't expose it
            pass

        # Always return success to prevent email enumeration
        return Response(
            {
                "message": "If an account with that email exists, a password reset link has been sent."
            },
            status=status.HTTP_200_OK,
        )

    @extend_schema(
        tags=["Password Management"],
        summary="Confirm Password Reset",
        description="Complete the password reset process using the token received via email.",
        request=PasswordResetConfirmSerializer,
        responses={
            200: inline_serializer(
                name="PasswordResetConfirmResponse",
                fields={"message": drf_serializers.CharField()},
            ),
            400: OpenApiResponse(description="Invalid or expired reset link"),
        },
    )
    @action(
        detail=False,
        methods=["POST"],
        permission_classes=[AllowAny],
        url_path="password-reset/confirm",
    )
    def confirm_password_reset(self, request):
        """
        Confirm password reset with token.

        POST /api/v1/users/password-reset/confirm/
        {
            "uid": "MjE",
            "token": "abc123-def456",
            "new_password": "NewSecurePass123!",
            "new_password_confirm": "NewSecurePass123!"
        }
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            uid = force_str(urlsafe_base64_decode(serializer.validated_data["uid"]))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {"error": "Invalid reset link."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Verify token
        if not default_token_generator.check_token(
            user, serializer.validated_data["token"]
        ):
            return Response(
                {"error": "Invalid or expired reset link."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Set new password and revoke all outstanding tokens
        user.set_password(serializer.validated_data["new_password"])
        user.token_version += 1
        user.refresh_jti = ""  # Invalidate current refresh token
        user.save(update_fields=["password", "token_version", "refresh_jti"])

        return Response(
            {"message": "Password has been reset successfully."},
            status=status.HTTP_200_OK,
        )

    
    @action(detail=False, methods=["POST"], permission_classes=[AllowAny], url_path="verify-email/request")
    def verify_email_request(self,request):
        """
        Endpoint to request a new verification email. Accepts an email address and, if a matching inactive user is found, sends a new verification email.

        POST api/v1/users/verify-email/request/?email=user@example.com 
        """
        email = request.data.get("email", "").lower().strip()
        if not email:
            return Response(
                {"error": "Email query parameter is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(email__iexact=email, is_active=False)
        except User.DoesNotExist:
            return Response(
                {
                    "message": "If an inactive account with that email exists, a new verification link has been sent."
                },
                status=status.HTTP_200_OK,
            )

        # Generate verification token
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        # Build verification URL (frontend should handle this route)
        verify_url = f"{settings.FRONTEND_URL}/verify-email?uid={uid}&token={token}"

        # Send verification email
        send_verification_email.delay(user.email, verify_url)

        return Response(
            {
                "message": "If an inactive account with that email exists, a new verification link has been sent."
            },
            status=status.HTTP_200_OK,
        )

    
    @extend_schema(
        tags=["Authentication"],
        summary="Verify Email",
        description="Verify user's email address using the token sent during registration. Returns JWT tokens for immediate login on success.",
        request=inline_serializer(
            name="VerifyEmailRequest",
            fields={
                "uid": drf_serializers.CharField(help_text="Base64-encoded user ID"),
                "token": drf_serializers.CharField(
                    help_text="Email verification token"
                ),
            },
        ),
        responses={
            200: inline_serializer(
                name="VerifyEmailSuccessResponse",
                fields={
                    "access": drf_serializers.CharField(help_text="JWT access token"),
                    "refresh": drf_serializers.CharField(help_text="JWT refresh token"),
                    "user": AuthUserSerializer(),
                    "message": drf_serializers.CharField(),
                },
            ),
            400: OpenApiResponse(description="Invalid or expired verification link"),
        },
    )
    @action(
        detail=False,
        methods=["POST"],
        permission_classes=[AllowAny],
        url_path="verify-email",
    )
    def verify_email(self, request):
        """
        Verify user email with token.

        POST /api/v1/users/verify-email/
        {
            "uid": "MjE",
            "token": "abc123-def456"
        }

        Returns JWT tokens on successful verification for immediate login.
        """
        uid = request.data.get("uid")
        token = request.data.get("token")

        if not uid or not token:
            return Response(
                {"error": "Missing uid or token."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user_id = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=user_id)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {"error": "Invalid verification link."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if user.is_active:
            return Response(
                {"message": "Email already verified."},
                status=status.HTTP_200_OK,
            )

        if not default_token_generator.check_token(user, token):
            return Response(
                {"error": "Invalid or expired verification link."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Activate user and mark email as verified
        user.is_active = True
        user.email_verified = True
        user.save(update_fields=["is_active", "email_verified"])

        # Generate tokens via the single centralized path
        tokens = get_tokens_for_user(user)

        return Response(
            {
                **tokens,
                "user": AuthUserSerializer(user).data,
                "message": "Email verified successfully.",
            },
            status=status.HTTP_200_OK,
        )


# =============================================================================
# SOCIAL AUTHENTICATION VIEWS
# =============================================================================


@extend_schema(
    tags=["Social Authentication"],
    summary="Google OAuth Login",
    description="Authenticate via Google OAuth. Accepts either an ID token (from Google Sign-In/One Tap) or an authorization code (from OAuth redirect flow). Returns JWT tokens on success.",
    request=inline_serializer(
        name="GoogleLoginRequest",
        fields={
            "id_token": drf_serializers.CharField(
                required=False, help_text="Google ID token from Sign-In/One Tap"
            ),
            "code": drf_serializers.CharField(
                required=False, help_text="Authorization code from OAuth redirect"
            ),
        },
    ),
    responses={
        200: inline_serializer(
            name="SocialLoginSuccessResponse",
            fields={
                "access": drf_serializers.CharField(help_text="JWT access token"),
                "refresh": drf_serializers.CharField(help_text="JWT refresh token"),
                "user": AuthUserSerializer(),
            },
        ),
        400: OpenApiResponse(description="Invalid token or code"),
    },
)
class _VersionedSocialLoginView(SocialLoginView):
    """
    Base class that overrides dj_rest_auth's SocialLoginView so that
    the JWT pair returned on social login is created via our centralized
    VersionedRefreshToken, guaranteeing identical claims to all other flows.
    """

    def get_response(self):
        tokens = get_tokens_for_user(self.user)
        user_data = AuthUserSerializer(self.user).data

        response_data = {
            **tokens,
            "user": user_data,
        }

        return Response(response_data, status=status.HTTP_200_OK)


class GoogleLogin(_VersionedSocialLoginView):
    """
    Google OAuth Login - Accepts either:

    1. ID Token (from Google Sign-In / One Tap):
       POST /api/v1/auth/social/google/
       { "id_token": "eyJhbGciOi..." }

    2. Authorization Code (from OAuth redirect flow):
       POST /api/v1/auth/social/google/
       { "code": "4/0AX4XfWh..." }

    Returns JWT tokens on success.
    """

    adapter_class = GoogleOAuth2Adapter
    client_class = OAuth2Client
    callback_url = settings.GOOGLE_CALLBACK_URL


@extend_schema(
    tags=["Social Authentication"],
    summary="GitHub OAuth Login",
    description="Authenticate via GitHub OAuth using an authorization code. Returns JWT tokens on success.",
    request=inline_serializer(
        name="GitHubLoginRequest",
        fields={
            "code": drf_serializers.CharField(
                help_text="Authorization code from GitHub OAuth"
            ),
        },
    ),
    responses={
        200: inline_serializer(
            name="GitHubLoginSuccessResponse",
            fields={
                "access": drf_serializers.CharField(help_text="JWT access token"),
                "refresh": drf_serializers.CharField(help_text="JWT refresh token"),
                "user": AuthUserSerializer(),
            },
        ),
        400: OpenApiResponse(description="Invalid authorization code"),
    },
)
class GitHubLogin(_VersionedSocialLoginView):
    """
    GitHub OAuth Login - Accepts authorization code:

    POST /api/v1/auth/social/github/
    { "code": "abc123..." }

    Returns JWT tokens on success.
    """

    adapter_class = GitHubOAuth2Adapter
    client_class = OAuth2Client
    callback_url = settings.GITHUB_CALLBACK_URL


@extend_schema(
    tags=["Social Authentication"],
    summary="Get OAuth URLs",
    description="Returns OAuth authorization URLs for Google and GitHub. Frontend should redirect users to these URLs to initiate the OAuth flow.",
    responses={
        200: inline_serializer(
            name="OAuthURLsResponse",
            fields={
                "google": drf_serializers.URLField(
                    help_text="Google OAuth authorization URL"
                ),
                "github": drf_serializers.URLField(
                    help_text="GitHub OAuth authorization URL"
                ),
            },
        ),
    },
)
@api_view(["GET"])
@permission_classes([AllowAny])
def get_oauth_urls(request):
    """
    Returns OAuth authorization URLs for frontend to redirect users.

    GET /api/v1/auth/social/urls/

    Frontend Flow:
    1. Call this endpoint to get the OAuth URL
    2. Redirect user to the URL (window.location.href = url)
    3. User authenticates with provider
    4. Provider redirects back with `code` param
    5. Frontend extracts `code` and POSTs to /api/v1/auth/social/google/ or /github/
    """
    # Generate a cryptographic state token to prevent login-CSRF.
    # The frontend must store this value and the callback must verify it.
    state = secrets.token_urlsafe(32)

    google_url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={settings.GOOGLE_CLIENT_ID}&"
        f"redirect_uri={settings.GOOGLE_CALLBACK_URL}&"
        "response_type=code&"
        "scope=openid%20email%20profile&"
        "access_type=offline&"
        "prompt=consent&"
        f"state={state}"
    )

    github_url = (
        "https://github.com/login/oauth/authorize?"
        f"client_id={settings.GITHUB_CLIENT_ID}&"
        f"redirect_uri={settings.GITHUB_CALLBACK_URL}&"
        f"scope=read:user%20user:email&"
        f"state={state}"
    )

    response = Response(
        {
            "google": google_url,
            "github": github_url,
            "state": state,
        }
    )
    # Also set the state in a secure, HTTP-only, SameSite cookie
    # so the callback can verify it server-side.
    response.set_cookie(
        "oauth_state",
        state,
        max_age=600,  # 10 minutes
        httponly=True,
        samesite="Lax",
        secure=not settings.DEBUG,
    )
    return response


# =============================================================================
# API KEY MANAGEMENT VIEWS
# =============================================================================


@extend_schema(
    tags=["Authentication"],
    summary="List My API Keys",
    description=(
        "Returns all API keys belonging to the authenticated user. "
        "The raw key is never returned — only the prefix, expiry, etc."
    ),
    responses={
        200: inline_serializer(
            name="APIKeyListResponse",
            fields={
                "id": drf_serializers.UUIDField(),
                "name": drf_serializers.CharField(),
                "prefix": drf_serializers.CharField(),
                "is_active": drf_serializers.BooleanField(),
                "created_at": drf_serializers.DateTimeField(),
                "last_used_at": drf_serializers.DateTimeField(),
                "expires_at": drf_serializers.DateTimeField(),
            },
        ),
    },
)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_api_keys(request):
    """Return all API keys for the authenticated user (metadata only)."""
    keys = (
        APIKey.objects.filter(user=request.user)
        .order_by("-created_at")
        .values(
            "id",
            "name",
            "prefix",
            "is_active",
            "created_at",
            "last_used_at",
            "expires_at",
        )
    )
    return Response(list(keys))


@extend_schema(
    tags=["Authentication"],
    summary="Create API Key",
    description=(
        "Generate a new API key with a custom name and expiration. "
        "The raw key is returned **only once** in the response."
    ),
    request=inline_serializer(
        name="CreateAPIKeyRequest",
        fields={
            "name": drf_serializers.CharField(
                required=False,
                help_text="A friendly label (default: 'default')",
            ),
            "expires_in_days": drf_serializers.IntegerField(
                required=False,
                help_text="Number of days until expiry (default: 365)",
            ),
        },
    ),
    responses={
        201: inline_serializer(
            name="CreateAPIKeyResponse",
            fields={
                "id": drf_serializers.UUIDField(),
                "name": drf_serializers.CharField(),
                "prefix": drf_serializers.CharField(),
                "api_key": drf_serializers.CharField(
                    help_text="The raw API key — shown only once!"
                ),
                "expires_at": drf_serializers.DateTimeField(),
                "created_at": drf_serializers.DateTimeField(),
            },
        ),
    },
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_api_key(request):
    """
    Create a brand-new API key with optional name and expiry.
    The raw key is returned once — the user must copy it now.
    """
    from datetime import timedelta

    # Security: limit number of active keys per user
    active_count = APIKey.objects.filter(user=request.user, is_active=True).count()

    if active_count >= APIKey.MAX_KEYS_PER_USER:
        return Response(
            {
                "error": f"Maximum of {APIKey.MAX_KEYS_PER_USER} active API keys allowed."
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    name = request.data.get("name", "default").strip() or "default"
    expires_in_days = request.data.get("expires_in_days", 90)

    try:
        expires_in_days = int(expires_in_days)

        if expires_in_days < 1:
            raise ValueError

        if expires_in_days > APIKey.MAX_EXPIRY_DAYS:
            return Response(
                {"error": f"Expiration period cannot exceed {APIKey.MAX_EXPIRY_DAYS} days."},
                status=status.HTTP_400_BAD_REQUEST,
            )

    except (ValueError, TypeError):
        return Response(
            {
                "error": f"expires_in_days must be a positive integer not greater than {APIKey.MAX_EXPIRY_DAYS}."
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    expires_at = timezone.now() + timedelta(days=expires_in_days)

    key_obj, raw_key = APIKey.create_key(request.user, name=name, expires_at=expires_at)

    return Response(
        {
            "id": key_obj.id,
            "name": key_obj.name,
            "prefix": key_obj.prefix,
            "api_key": raw_key,
            "expires_at": key_obj.expires_at,
            "created_at": key_obj.created_at,
        },
        status=status.HTTP_201_CREATED,
    )


@extend_schema(
    tags=["Authentication"],
    summary="Delete API Key",
    description="Permanently delete the user's API key by its ID.",
    responses={
        200: inline_serializer(
            name="DeleteAPIKeyResponse",
            fields={"message": drf_serializers.CharField()},
        ),
        404: OpenApiResponse(description="API key not found"),
    },
)
@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def delete_api_key(request, key_id):
    """Permanently delete one API key belonging to the authenticated user."""
    deleted, _ = APIKey.objects.filter(pk=key_id, user=request.user).delete()

    if not deleted:
        return Response(
            {"error": "API key not found."},
            status=status.HTTP_404_NOT_FOUND,
        )
    return Response({"message": "API key deleted."})


# =============================================================================
# BACKEND CALLBACK VIEWS (For testing without frontend)
# =============================================================================


@extend_schema(
    tags=["Social Authentication"],
    summary="Google OAuth Callback",
    description="Handles Google OAuth callback redirect. Exchanges the authorization code for JWT tokens. This endpoint is called by Google after user authorization.",
    parameters=[
        OpenApiParameter(
            name="code",
            description="Authorization code from Google",
            required=False,
            type=str,
        ),
        OpenApiParameter(
            name="error",
            description="Error message if authorization failed",
            required=False,
            type=str,
        ),
    ],
    responses={
        200: inline_serializer(
            name="GoogleCallbackSuccessResponse",
            fields={
                "access": drf_serializers.CharField(),
                "refresh": drf_serializers.CharField(),
                "user": AuthUserSerializer(),
            },
        ),
        400: OpenApiResponse(description="Authorization failed or no code provided"),
        502: OpenApiResponse(description="Failed to contact auth service"),
    },
)
@api_view(["GET"])
@permission_classes([AllowAny])
def google_callback(request):
    """
    Handles Google OAuth callback redirect.
    Exchanges code for tokens and returns JWT.

    Register this URL in Google Cloud Console:
    http://localhost:8000/api/v1/auth/social/google/callback/
    """
    code = request.GET.get("code")
    error = request.GET.get("error")
    state = request.GET.get("state")

    if error:
        return Response(
            {"error": error, "detail": "Google OAuth authorization failed"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if not code:
        return Response(
            {"error": "No code provided"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Validate state parameter to prevent login-CSRF
    expected_state = request.COOKIES.get("oauth_state")
    if (
        not state
        or not expected_state
        or not secrets.compare_digest(state, expected_state)
    ):
        logger.warning("OAuth state mismatch in Google callback")
        return _social_auth_error_response(
            "Invalid OAuth state. Please try logging in again."
        )

    # Post to internal social login endpoint
    token_url = request.build_absolute_uri("/api/v1/auth/social/google/")

    try:
        response = requests.post(
            token_url,
            json={"code": code},
            timeout=10,
        )
        if response.status_code == 200:
            resp = _social_auth_redirect_response(response.json())
            resp.delete_cookie("oauth_state")
            return resp
        return _social_auth_error_response(
            "Google authentication failed. Please try again."
        )
    except requests.RequestException:
        return _social_auth_error_response("Failed to contact auth service.")


@extend_schema(
    tags=["Social Authentication"],
    summary="GitHub OAuth Callback",
    description="Handles GitHub OAuth callback redirect. Exchanges the authorization code for JWT tokens. This endpoint is called by GitHub after user authorization.",
    parameters=[
        OpenApiParameter(
            name="code",
            description="Authorization code from GitHub",
            required=False,
            type=str,
        ),
        OpenApiParameter(
            name="error",
            description="Error message if authorization failed",
            required=False,
            type=str,
        ),
    ],
    responses={
        200: inline_serializer(
            name="GitHubCallbackSuccessResponse",
            fields={
                "access": drf_serializers.CharField(),
                "refresh": drf_serializers.CharField(),
                "user": AuthUserSerializer(),
            },
        ),
        400: OpenApiResponse(description="Authorization failed or no code provided"),
        502: OpenApiResponse(description="Failed to contact auth service"),
    },
)
@api_view(["GET"])
@permission_classes([AllowAny])
def github_callback(request):
    """
    Handles GitHub OAuth callback redirect.

    Register this URL in GitHub Developer Settings:
    http://localhost:8000/api/v1/auth/social/github/callback/
    """
    code = request.GET.get("code")
    error = request.GET.get("error")
    state = request.GET.get("state")

    if error:
        return Response(
            {"error": error, "detail": "GitHub OAuth authorization failed"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if not code:
        return Response(
            {"error": "No code provided"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Validate state parameter to prevent login-CSRF
    expected_state = request.COOKIES.get("oauth_state")
    if (
        not state
        or not expected_state
        or not secrets.compare_digest(state, expected_state)
    ):
        logger.warning("OAuth state mismatch in GitHub callback")
        return _social_auth_error_response(
            "Invalid OAuth state. Please try logging in again."
        )

    token_url = request.build_absolute_uri("/api/v1/auth/social/github/")

    try:
        response = requests.post(
            token_url,
            json={"code": code},
            timeout=10,
        )
        if response.status_code == 200:
            resp = _social_auth_redirect_response(response.json())
            resp.delete_cookie("oauth_state")
            return resp
        return _social_auth_error_response(
            "GitHub authentication failed. Please try again."
        )
    except requests.RequestException:
        return _social_auth_error_response("Failed to contact auth service.")


# =============================================================================
# SOCIAL AUTH REDIRECT HELPERS
# =============================================================================


def _social_auth_redirect_response(token_data):
    """
    Redirects to the frontend callback page with tokens as URL params.
    The frontend (on its own origin) stores them in localStorage.
    """
    frontend_url = getattr(settings, "FRONTEND_URL", "")
    code = str(uuid.uuid4())
    cache_key = f"social_auth_{code}"
    print(cache_key)
    cache.set(cache_key, token_data, timeout=60)  # Store tokens for
    redirect_url = f"{frontend_url}/oauth/callback?code={code}"

    return HttpResponseRedirect(redirect_url)


def _social_auth_error_response(message):
    frontend_url = getattr(settings, "FRONTEND_URL", "http://localhost:5173")
    params = urlencode({"error": message})
    return HttpResponseRedirect(f"{frontend_url}/oauth/callback?{params}")


class ExchangeTokenView(APIView):
    """
    Exchanges a short-lived authorization code for JWT tokens.
    This pattern prevents exposing tokens in the URL.
    """

    permission_classes = [AllowAny]
    throttle_classes = [SocialExchangeRateThrottle]
    throttle_scope = "social_exchange"  # Applies the '5/m' rate limit

    def post(self, request):
        code = request.data.get("code")
        print(code)

        # 1. Validate existence
        if not code:
            return Response(
                {"error": "Authorization code is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 2. Validate UUID format (prevent cache key injection attacks)
        try:
            uuid.UUID(str(code))
        except ValueError:
            logger.warning(
                f"Invalid UUID format attempted from IP: {self._get_client_ip(request)}"
            )
            return Response(
                {"error": "Invalid code format."}, status=status.HTTP_400_BAD_REQUEST
            )

        # 3. Construct cache key and lookup
        cache_key = f"social_auth_{code}"
        token_data = cache.get(cache_key)

        if not token_data:
            logger.warning(
                f"Failed token exchange attempt for code: {code} (Expired or Invalid)"
            )
            return Response(
                {"error": "Invalid or expired code. Please try logging in again."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 4. Single-use enforcement: Delete immediately
        cache.delete(cache_key)

        # 5. Return tokens
        return Response(token_data, status=status.HTTP_200_OK)

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip
