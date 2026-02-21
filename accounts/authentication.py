# accounts/authentication.py
"""
Authentication classes for the portfolio API.

Supports two mechanisms:
1. **API Key** — long-lived key sent via ``X-API-Key`` header.
   Ideal for external portfolio sites consuming the API.
2. **Versioned JWT** — primary authentication for the dashboard frontend.
"""

import logging

from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken

logger = logging.getLogger(__name__)
User = get_user_model()


# =========================================================================
# API Key Authentication (for external API consumers)
# =========================================================================
class APIKeyAuthentication(BaseAuthentication):
    """
    Authenticate requests via the ``X-API-Key`` header.

    The key is hashed with HMAC-SHA256 and looked up against the
    ``APIKey.key_hash`` column, so the raw secret is never stored.

    Includes per-IP rate limiting on failed attempts (max 5 per 5 min).
    """

    HEADER = "HTTP_X_API_KEY"
    MAX_FAILURES = 5
    FAILURE_WINDOW = 300  # seconds

    def authenticate(self, request):
        raw_key = request.META.get(self.HEADER)
        if not raw_key:
            return None  # Let other authenticators try

        # Rate limit by IP
        ip = self._get_client_ip(request)
        cache_key = f"apikey_fail:{ip}"
        failures = cache.get(cache_key, 0)

        if failures >= self.MAX_FAILURES:
            raise exceptions.AuthenticationFailed(
                "Too many invalid API key attempts. Try again later."
            )

        from .models import APIKey

        key_hash = APIKey.hash_key(raw_key)

        try:
            api_key = APIKey.objects.select_related("user").get(key_hash=key_hash)
        except APIKey.DoesNotExist:
            cache.set(cache_key, failures + 1, timeout=self.FAILURE_WINDOW)
            raise exceptions.AuthenticationFailed("Invalid API key.")

        if not api_key.is_valid:
            raise exceptions.AuthenticationFailed("API key is inactive or expired.")

        if not api_key.user.is_active:
            raise exceptions.AuthenticationFailed("User account is disabled.")

        # Success — reset failure counter and record usage
        cache.delete(cache_key)
        api_key.record_usage()

        return (api_key.user, api_key)

    def authenticate_header(self, request):
        return "X-API-Key"

    @staticmethod
    def _get_client_ip(request):
        x_forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded:
            return x_forwarded.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "")


# =========================================================================
# Versioned JWT Authentication (kept for API consumers / backwards compat)
# =========================================================================
class VersionedJWTAuthentication(JWTAuthentication):
    """
    Extends SimpleJWT's default authentication to enforce that every
    validated token carries a `token_version` claim matching the user's
    current version.  If it doesn't match, the token has been revoked
    (via logout, password change, etc.) and is rejected.
    """

    def get_user(self, validated_token):
        user = super().get_user(validated_token)

        token_version = validated_token.get("token_version")
        if token_version is None:
            logger.warning("JWT missing token_version claim for user %s", user.pk)
            raise InvalidToken("Missing token_version claim")

        if token_version != user.token_version:
            logger.info(
                "Revoked JWT used for user %s (token v%s != current v%s)",
                user.pk,
                token_version,
                user.token_version,
            )
            raise InvalidToken("Token has been revoked")

        return user
