from django.shortcuts import render
from drf_spectacular.utils import OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import MethodNotAllowed
from rest_framework.response import Response

from commons.permissions import IsAuthenticatedAndOwner

from .models import Skill, SkillCategory
from .serializers import SkillCategorySerializer, SkillSerializer


# Create your views here.
@extend_schema_view(
    list=extend_schema(
        tags=["Skill Categories"],
        summary="List Skill Categories",
        description="Retrieve all skill categories belonging to the authenticated user with their associated skills.",
        responses={
            200: SkillCategorySerializer(many=True),
            401: OpenApiResponse(
                description="Authentication credentials were not provided"
            ),
        },
    ),
    create=extend_schema(exclude=True),
    update=extend_schema(exclude=True),
    retrieve=extend_schema(exclude=True),
    partial_update=extend_schema(exclude=True),
    destroy=extend_schema(exclude=True),
)
class SkillCategoryViewSet(viewsets.ModelViewSet):
    """ViewSet for managing skill categories."""

    serializer_class = SkillCategorySerializer
    permission_classes = [IsAuthenticatedAndOwner]

    def get_queryset(self):
        """
        Optimize: Prefetch all skills for each category.
        This turns N+1 queries into just 2 queries.
        """
        return SkillCategory.objects.filter(user=self.request.user).prefetch_related(
            "items"
        )

    def create(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)

    def update(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)

    def partial_update(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)


@extend_schema_view(
    list=extend_schema(
        tags=["Skills"],
        summary="List Skills",
        description="Retrieve all skills belonging to the authenticated user with their category information.",
        responses={
            200: SkillSerializer(many=True),
            401: OpenApiResponse(
                description="Authentication credentials were not provided"
            ),
        },
    ),
    create=extend_schema(exclude=True),
    update=extend_schema(exclude=True),
    retrieve=extend_schema(exclude=True),
    partial_update=extend_schema(exclude=True),
    destroy=extend_schema(exclude=True),
)
class SkillViewSet(viewsets.ModelViewSet):
    """ViewSet for managing individual skills."""

    serializer_class = SkillSerializer
    permission_classes = [IsAuthenticatedAndOwner]

    def get_queryset(self):
        """
        Optimize: Select the category in the same query.
        This turns N+1 queries into just 1 query.
        """
        return Skill.objects.filter(user=self.request.user).select_related("category")

    def create(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)

    def update(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)

        raise MethodNotAllowed(request.method)

    def partial_update(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)
