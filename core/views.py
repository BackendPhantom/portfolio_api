"""
Core API views — health check, data export, activity feed, public stats.

These views provide cross-cutting platform functionality that does not
belong to any single domain app (accounts, projects, skills).
"""

from django.db import connection
from django.http import JsonResponse
from django.utils import timezone
from drf_spectacular.utils import (
    OpenApiResponse,
    extend_schema,
    inline_serializer,
)
from rest_framework import serializers as drf_serializers
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from core.models import ActivityLog


# =========================================================================
# Health Check (public, no auth)
# =========================================================================
def health_check(request):
    """
    Lightweight health-check endpoint for load balancers and uptime monitors.

    Returns JSON with ``status`` ("healthy" | "unhealthy") and a
    ``database`` field indicating connection state.

    **GET /api/v1/health/**

    200 — system is healthy
    503 — database or other dependency is unreachable
    """
    health = {"status": "healthy"}

    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        health["database"] = "connected"
    except Exception as e:
        health["status"] = "unhealthy"
        health["database"] = str(e)

    status_code = 200 if health["status"] == "healthy" else 503
    return JsonResponse(health, status=status_code)


# =========================================================================
# Data Export
# =========================================================================
@extend_schema(
    tags=["Core"],
    summary="Export User Data",
    description=(
        "Export the authenticated user's entire portfolio as a single JSON "
        "payload (profile, projects, skill categories, skills). The response "
        "includes a Content-Disposition header for direct file download."
    ),
    responses={
        200: OpenApiResponse(description="JSON file containing all user data"),
        401: OpenApiResponse(
            description="Authentication credentials were not provided"
        ),
    },
)
class DataExportView(APIView):
    """
    Export all user data as a single JSON payload for backup / portability.

    **GET /api/v1/export/**

    Returns a downloadable JSON file containing the user's profile,
    projects, skill categories, and skills.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Serialize the authenticated user's full portfolio into JSON."""
        user = request.user

        from accounts.serializers import UserProfileSerializer
        from projects.models import Project
        from projects.serializers import ProjectSerializer
        from skills.models import Skill, SkillCategory
        from skills.serializers import SkillCategorySerializer, SkillSerializer

        data = {
            "exported_at": timezone.now().isoformat(),
            "user": UserProfileSerializer(user).data,
            "projects": ProjectSerializer(
                Project.objects.filter(user=user),
                many=True,
                context={"request": request},
            ).data,
            "skill_categories": SkillCategorySerializer(
                SkillCategory.objects.filter(user=user), many=True
            ).data,
            "skills": SkillSerializer(Skill.objects.filter(user=user), many=True).data,
        }

        response = Response(data)
        response["Content-Disposition"] = (
            f'attachment; filename="portfolio_export_{timezone.now():%Y%m%d}.json"'
        )
        return response


# =========================================================================
# Recent Activity Feed
# =========================================================================
@extend_schema(
    tags=["Core"],
    summary="Recent Activity Feed",
    description=(
        "Return the 20 most recent activity-log entries for the authenticated user. "
        "Each entry contains the action performed, a human-readable object "
        "representation, and the timestamp."
    ),
    responses={
        200: inline_serializer(
            name="ActivityLogEntry",
            fields={
                "action": drf_serializers.CharField(),
                "object_repr": drf_serializers.CharField(),
                "timestamp": drf_serializers.DateTimeField(),
            },
            many=True,
        ),
        401: OpenApiResponse(
            description="Authentication credentials were not provided"
        ),
    },
)
class RecentActivityView(APIView):
    """
    Return the 20 most recent activity-log entries for the current user.

    **GET /api/v1/activity/**
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Query the last 20 activity log rows for the authenticated user."""
        logs = ActivityLog.objects.filter(user=request.user).values(
            "action", "object_repr", "timestamp"
        )[:20]
        return Response(list(logs))


# =========================================================================
# Public Stats
# =========================================================================
@extend_schema(
    tags=["Core"],
    summary="Public Platform Stats",
    description=(
        "Return simple aggregate counts across the platform. "
        "This is a public endpoint — no authentication required."
    ),
    responses={
        200: inline_serializer(
            name="PlatformStats",
            fields={
                "total_skills": drf_serializers.IntegerField(),
                "total_projects": drf_serializers.IntegerField(),
                "generated_at": drf_serializers.DateTimeField(),
            },
        ),
    },
)
class StatsView(APIView):
    """
    Return simple aggregate counts for public stats (skills, projects).

    **GET /api/v1/stats/**

    Public endpoint — no authentication required.
    """

    permission_classes = []

    def get(self, request):
        """Compute and return platform-wide aggregate counts."""
        from projects.models import Project
        from skills.models import Skill

        data = {
            "total_skills": Skill.objects.count(),
            "total_projects": Project.objects.count(),
            "generated_at": timezone.now().isoformat(),
        }
        return Response(data)
