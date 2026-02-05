from django.urls import include, path
from rest_framework import routers

from skills.views import SkillCategoryViewSet, SkillViewSet

router = routers.DefaultRouter()

# Order matters: Specific paths first, generic paths last
# Generates: api/v1/skills/categories/
router.register(r"categories", SkillCategoryViewSet, basename="skill-categories")

# Generates: api/v1/skills/
router.register(r"", SkillViewSet, basename="skills")

urlpatterns = [
    path("", include(router.urls)),
]
