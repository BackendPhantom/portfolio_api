"""
Testing settings — fast password hasher, in-memory DB, local email.
"""

from .base import *  # noqa: F401, F403

DEBUG = False

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

# Faster password hashing for tests
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

# Capture emails in memory
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
