"""
Rate-limiting throttle classes for authentication endpoints.
"""

from rest_framework.throttling import AnonRateThrottle, ScopedRateThrottle


class LoginRateThrottle(AnonRateThrottle):
    """5 login attempts per minute from the same IP."""

    scope = "login"


class SignupRateThrottle(AnonRateThrottle):
    """3 signup attempts per minute from the same IP."""

    scope = "signup"


class PasswordResetRateThrottle(AnonRateThrottle):
    """3 password-reset requests per minute from the same IP."""

    scope = "password_reset"


class SocialExchangeRateThrottle(AnonRateThrottle):
    """5 social auth token exchanges per minute from the same IP."""

    scope = "social_exchange"
