"""
Centralized JWT token classes for the portfolio API.

ALL token issuance — custom login, social login, email verification,
token refresh — MUST flow through these classes so that every JWT
carries an identical, validated set of claims including `token_version`.

Refresh token single-use is enforced via a hashed JTI stored on the User
model.  On every issuance the stored JTI is overwritten, so the previous
refresh token becomes invalid without requiring a blacklist table.
"""

import hashlib

from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken


def _hash_jti(jti: str) -> str:
    """Return a hex SHA-256 digest of a JTI string."""
    return hashlib.sha256(jti.encode()).hexdigest()


class VersionedAccessToken(AccessToken):
    """Access token that always carries the token_version claim."""

    @classmethod
    def for_user(cls, user):
        token = super().for_user(user)
        token["token_version"] = user.token_version
        return token


class VersionedRefreshToken(RefreshToken):
    """
    Refresh token that:
    1. Injects `token_version` into BOTH the refresh token itself
       and the access token it produces.
    2. Each token's JTI is hashed and stored on the User so only
       the latest refresh token is accepted.
    """

    # Override the access_token_class so .access_token uses our versioned class
    access_token_class = VersionedAccessToken

    @classmethod
    def for_user(cls, user):
        token = super().for_user(user)
        token["token_version"] = user.token_version
        return token


def get_tokens_for_user(user):
    """
    Single entry point for issuing a JWT pair for any user,
    regardless of auth method (email/password, social, email verify).

    Creates the token pair, then persists the hashed refresh JTI on the
    user so that only this refresh token will be accepted on the next
    refresh request.  Any previously issued refresh token is implicitly
    invalidated.

    Returns a dict with 'access' and 'refresh' string tokens.
    """
    refresh = VersionedRefreshToken.for_user(user)

    # Persist the hashed JTI so we can validate it on refresh
    user.refresh_jti = _hash_jti(refresh["jti"])
    user.save(update_fields=["refresh_jti"])

    return {
        "access": str(refresh.access_token),
        "refresh": str(refresh),
    }
