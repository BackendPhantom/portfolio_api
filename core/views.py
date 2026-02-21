"""
Core API views — health check, data export, activity feed.
"""

from django.db import connection
from django.http import JsonResponse
from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from core.models import ActivityLog


# =========================================================================
# Health Check (public, no auth)
# =========================================================================
def health_check(request):
    """Lightweight health check for load balancers and monitoring."""
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
class DataExportView(APIView):
    """Export all user data as a single JSON payload for backup/portability."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
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
class RecentActivityView(APIView):
    """Return the 20 most recent activity log entries for the current user."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        logs = ActivityLog.objects.filter(user=request.user).values(
            "action", "object_repr", "timestamp"
        )[:20]
        return Response(list(logs))


class StatsView(APIView):
    """Return simple aggregate counts for public stats (skills, projects)."""

    # Public endpoint — no authentication required.
    permission_classes = []

    def get(self, request):
        from projects.models import Project
        from skills.models import Skill

        data = {
            "total_skills": Skill.objects.count(),
            "total_projects": Project.objects.count(),
            "generated_at": timezone.now().isoformat(),
        }
        return Response(data)
