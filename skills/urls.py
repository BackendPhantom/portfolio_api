from django.urls import include, path
from rest_framework import routers

from skills.views import SkillCategoryViewSet, SkillViewSet

router = routers.DefaultRouter()
router.register(r"skill-categories", SkillCategoryViewSet)
router.register(r"skills-list", SkillViewSet)

urlpatterns = [
    path("", include(router.urls)),
]
