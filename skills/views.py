from drf_spectacular.utils import OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import MethodNotAllowed
from rest_framework.response import Response

from commons.permissions import IsAuthenticatedAndOwner

from .models import Skill, SkillCategory
from .serializers import SkillCategorySerializer, SkillSerializer


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
    """
    Manage skill categories for the authenticated user.

    Only the ``list`` action is publicly exposed (returns categories with
    nested skills).  Create, update, partial_update, retrieve, and destroy
    are disabled and return ``405 Method Not Allowed``.
    """

    serializer_class = SkillCategorySerializer
    permission_classes = [IsAuthenticatedAndOwner]

    def get_queryset(self):
        """
        Return categories owned by the current user with prefetched skills.

        Uses ``prefetch_related('items')`` to avoid N+1 queries when the
        serializer renders nested skill data.
        """
        return SkillCategory.objects.all()

    def create(self, request, *args, **kwargs):
        """Disabled — categories are created via the admin or data import."""
        raise MethodNotAllowed(request.method)

    def update(self, request, *args, **kwargs):
        """Disabled — categories are updated via the admin or data import."""
        raise MethodNotAllowed(request.method)

    def partial_update(self, request, *args, **kwargs):
        """Disabled — categories are updated via the admin or data import."""
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
    """
    Manage individual skills for the authenticated user.

    Only the ``list`` action is publicly exposed (returns skills with their
    category info).  Create, update, partial_update, retrieve, and destroy
    are disabled and return ``405 Method Not Allowed``.
    """

    serializer_class = SkillSerializer
    permission_classes = [IsAuthenticatedAndOwner]

    def get_queryset(self):
        """
        Return skills owned by the current user with their category
        eagerly loaded via ``select_related`` to avoid N+1 queries.
        """
        return Skill.objects.filter(user=self.request.user).select_related("category")

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()  # This calls the .create() method in your serializer
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        """Disabled — skills are updated via the admin or data import."""
        raise MethodNotAllowed(request.method)

    def partial_update(self, request, *args, **kwargs):
        """Disabled — skills are updated via the admin or data import."""
        raise MethodNotAllowed(request.method)
