from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    GitHubLogin,
    GoogleLogin,
    LoginView,
    LogoutView,
    SignupViewset,
    UserProfileViewset,
    get_oauth_urls,
    github_callback,
    google_callback,
)

router = DefaultRouter()
router.register(r"", UserProfileViewset, basename="users")

# =============================================================================
# URL PATTERNS
# =============================================================================
# All URLs are prefixed with /api/v1/ from core/urls.py
#
# Authentication: /api/v1/auth/...
# Users:          /api/v1/users/...
# =============================================================================

auth_patterns = [
    # --- Email/Password Auth ---
    path("signup/", SignupViewset.as_view(), name="signup"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    # --- Social Auth ---
    path("social/google/", GoogleLogin.as_view(), name="google_login"),
    path("social/github/", GitHubLogin.as_view(), name="github_login"),
    path("social/urls/", get_oauth_urls, name="oauth_urls"),
    # --- OAuth Callbacks (register these in provider consoles) ---
    path("social/google/callback/", google_callback, name="google_callback"),
    path("social/github/callback/", github_callback, name="github_callback"),
]

user_patterns = router.urls

urlpatterns = [
    path("auth/", include(auth_patterns)),
    path("users/", include(user_patterns)),
]
