"""
Development settings — local dev with SQLite, console email, all CORS.
"""

from .base import *  # noqa: F401, F403

DEBUG = True
ALLOWED_HOSTS = ["*"]

# SQLite for quick local dev
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# Print emails to console
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# Allow all origins in dev
CORS_ALLOW_ALL_ORIGINS = True

# JWT cookie not secure in dev
# REST_AUTH["JWT_AUTH_SECURE"] = False

# CACHES = {
#     "default": {
#         "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
#         "LOCATION": "unique-snowflake",
#     }
# }

