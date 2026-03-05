"""
Centralised rate-limiting throttle classes for the entire project.
All apps import from here instead of defining their own throttle files.
"""

from rest_framework.throttling import AnonRateThrottle


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


class ContactRateThrottle(AnonRateThrottle):
    """3 contact-form submissions per hour from the same IP."""

    scope = "contact"
