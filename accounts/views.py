from urllib.parse import urlencode

import requests
from allauth.socialaccount.providers.github.views import GitHubOAuth2Adapter
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.views import SocialLoginView
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.shortcuts import redirect, render
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.exceptions import MethodNotAllowed, NotFound
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from commons.permissions import IsSelf

from .serializers import (
    AuthUserSerializer,
    ChangePasswordSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    PublicUserProfileSerializer,
    UserProfileSerializer,
    UserRegistrationSerializer,
)

User = get_user_model()




# =============================================================================
# AUTHENTICATION VIEWS
# =============================================================================


class SignupViewset(GenericAPIView):
    """
    User registration with email and password.
    Requires email verification before account becomes active.
    """

    permission_classes = [AllowAny]
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
        try:
            send_mail(
                subject="Verify your email address",
                message=(
                    f"Welcome to our platform!\n\n"
                    f"Please click the following link to verify your email address:\n"
                    f"{verify_url}\n\n"
                    f"This link will expire in 24 hours.\n\n"
                    f"If you didn't create this account, please ignore this email."
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
        except Exception:
            # If email fails, still return success but log the error
            pass

        return Response(
            {
                "message": "Account created successfully. Please check your email to verify your account.",
                "email": user.email,
            },
            status=status.HTTP_201_CREATED,
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

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)

        return Response(
            {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "user": AuthUserSerializer(user).data,
            },
            status=status.HTTP_200_OK,
        )


class LogoutView(APIView):
    """
  
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        user.token_version += 1
        user.save(update_fields=["token_version"])

        return Response(
            {"message": "Logged out from all devices"},
            status=200,
        )


# =============================================================================
# PROFILE VIEWS
# =============================================================================
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

    @action(
        detail=False,
        methods=["POST"],
        permission_classes=[AllowAny],
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
            send_mail(
                subject="Password Reset Request",
                message=f"Click the following link to reset your password: {reset_url}\n\nThis link will expire in 24 hours.\n\nIf you didn't request this, please ignore this email.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
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

        # Set new password
        user.set_password(serializer.validated_data["new_password"])
        user.save()

        return Response(
            {"message": "Password has been reset successfully."},
            status=status.HTTP_200_OK,
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

        # Activate user
        user.is_active = True
        user.save()

        # Generate tokens for immediate login
        refresh = RefreshToken.for_user(user)

        return Response(
            {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "user": AuthUserSerializer(user).data,
                "message": "Email verified successfully.",
            },
            status=status.HTTP_200_OK,
        )


# =============================================================================
# SOCIAL AUTHENTICATION VIEWS
# =============================================================================


class GoogleLogin(SocialLoginView):
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


class GitHubLogin(SocialLoginView):
    """
    GitHub OAuth Login - Accepts authorization code:

    POST /api/v1/auth/social/github/
    { "code": "abc123..." }

    Returns JWT tokens on success.
    """

    adapter_class = GitHubOAuth2Adapter
    client_class = OAuth2Client
    callback_url = settings.GITHUB_CALLBACK_URL


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
    google_url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={settings.GOOGLE_CLIENT_ID}&"
        f"redirect_uri={settings.GOOGLE_CALLBACK_URL}&"
        "response_type=code&"
        "scope=openid%20email%20profile&"
        "access_type=offline&"
        "prompt=consent"
    )

    github_url = (
        "https://github.com/login/oauth/authorize?"
        f"client_id={settings.GITHUB_CLIENT_ID}&"
        f"redirect_uri={settings.GITHUB_CALLBACK_URL}&"
        "scope=read:user%20user:email"
    )

    return Response(
        {
            "google": google_url,
            "github": github_url,
        }
    )


# =============================================================================
# BACKEND CALLBACK VIEWS (For testing without frontend)
# =============================================================================


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

    # Post to internal social login endpoint
    token_url = request.build_absolute_uri("/api/v1/auth/social/google/")

    try:
        response = requests.post(
            token_url,
            json={"code": code},
            timeout=10,
        )
        return Response(response.json(), status=response.status_code)
    except requests.RequestException as exc:
        return Response(
            {"error": "Failed to contact auth service", "detail": str(exc)},
            status=status.HTTP_502_BAD_GATEWAY,
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

    token_url = request.build_absolute_uri("/api/v1/auth/social/github/")

    try:
        response = requests.post(
            token_url,
            json={"code": code},
            timeout=10,
        )
        return Response(response.json(), status=response.status_code)
    except requests.RequestException as exc:
        return Response(
            {"error": "Failed to contact auth service", "detail": str(exc)},
            status=status.HTTP_502_BAD_GATEWAY,
        )
