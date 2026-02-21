"""
URL configuration for core project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.conf import settings
from django.contrib import admin
from django.http import JsonResponse
from django.urls import include, path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

from .views import DataExportView, RecentActivityView, health_check, StatsView

# =============================================================================
# API URL PATTERNS
# =============================================================================
# All API endpoints are grouped under /api/v1/
#
# /api/v1/auth/...      - Authentication (signup, login, logout, social)
# /api/v1/users/...     - User profiles and account management
# /api/v1/projects/...  - Portfolio projects
# /api/v1/skills/...    - Skills and skill categories
# =============================================================================

api_v1_patterns = [
    path("", include("accounts.urls")),  # auth/ and users/
    path("projects/", include("projects.urls")),
    path("skills/", include("skills.urls")),
    path("export/", DataExportView.as_view(), name="data-export"),
    path("activity/", RecentActivityView.as_view(), name="recent-activity"),
    path("stats/", StatsView.as_view(), name="stats"),
]


# ---- Unsupported API version catch-all (Architecture #17) ----
def unsupported_version(request, version, rest=""):
    return JsonResponse(
        {
            "success": False,
            "status_code": 400,
            "message": f"API version '{version}' is not supported.",
            "supported_versions": ["v1"],
        },
        status=400,
    )


# =============================================================================
# FRONTEND URL PATTERNS
# =============================================================================
# HTML pages served by Django templates. Data is loaded client-side via the API.
# =============================================================================


urlpatterns = [
    # Health check (no auth)
    path("health/", health_check, name="health-check"),
    # Frontend pages
    # Admin
    path("admin/", admin.site.urls),
    # API
    path("api/v1/", include(api_v1_patterns)),
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    # Optional UI:
    path(
        "api/schema/swagger/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
    path(
        "api/schema/redoc/",
        SpectacularRedocView.as_view(url_name="schema"),
        name="redoc",
    ),
    # Catch-all for unsupported API versions
    path("api/<str:version>/", unsupported_version),
    path("api/<str:version>/<path:rest>", unsupported_version),
    # path('auth/', include('rest_framework.urls'))
]
