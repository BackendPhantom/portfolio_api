from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    ExchangeTokenView,
    GitHubLogin,
    GoogleLogin,
    LoginView,
    LogoutView,
    SignupViewset,
    UserProfileViewset,
    VersionedTokenRefreshView,
    create_api_key,
    delete_api_key,
    get_oauth_urls,
    github_callback,
    google_callback,
    list_api_keys,
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
    # --- Token Refresh (validates token_version before issuing new pair) ---
    path("token/refresh/", VersionedTokenRefreshView.as_view(), name="token_refresh"),
    # --- API Key Management ---
    path("api-keys/", list_api_keys, name="api_key_list"),
    path("api-keys/create/", create_api_key, name="api_key_create"),
    path("api-keys/<uuid:key_id>/", delete_api_key, name="api_key_delete"),
    # --- Social Auth ---
    path("social/google/", GoogleLogin.as_view(), name="google_login"),
    path("social/github/", GitHubLogin.as_view(), name="github_login"),
    path("social/urls/", get_oauth_urls, name="oauth_urls"),
    # --- OAuth Callbacks (register these in provider consoles) ---
    path("social/google/callback/", google_callback, name="google_callback"),
    path("social/github/callback/", github_callback, name="github_callback"),
    path("social/exchange/", ExchangeTokenView.as_view(), name="social_token_exchange"),
]

user_patterns = router.urls

urlpatterns = [
    path("auth/", include(auth_patterns)),
    path("users/", include(user_patterns)),
]
