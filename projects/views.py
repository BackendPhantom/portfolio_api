from django.shortcuts import get_object_or_404
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import MethodNotAllowed
from rest_framework.response import Response

from commons.pagination import PortfolioPagination
from commons.permissions import IsAuthenticatedAndOwner, ProjectPermission

from .models import Project
from .serializers import ProjectSerializer


class ProjectViewSet(viewsets.ModelViewSet):
    queryset = Project.objects.all()
    serializer_class = ProjectSerializer
    pagination_class = PortfolioPagination
    permission_classes = [IsAuthenticatedAndOwner, ProjectPermission]

    def get_queryset(self):
        return Project.objects.filter(user=self.request.user).prefetch_related(
            "tech_stack", "tech_stack__category"
        )

    # --- Disable Standard Methods ---
    def list(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)

    def create(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)

    def retrieve(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)

    def update(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)

    def destroy(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)

    # --- Custom Actions ---

    # 1. LIST (GET)
    # url: /projects/my-projects/
    @action(detail=False, methods=["GET"], url_path="my-projects")
    def my_projects(self, request):
        queryset = self.get_queryset()

        # KEY CHANGE: You must manually call the paginator inside a custom action
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        # Fallback if pagination is turned off
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    # 2. CREATE (POST)
    # url: /projects/create-new/
    @action(detail=False, methods=["POST"], url_path="create-new")
    def create_project(self, request):
        # We pass the request context so the serializer can access request.user
        serializer = self.get_serializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()  # This calls the .create() method in your serializer
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    # 3. RETRIEVE (GET Single)
    # url: /projects/{pk}/details/
    @action(detail=True, methods=["GET"], url_path="details")
    def project_details(self, request, pk=None):
        instance = self.get_object()  # get_object() handles 404s automatically
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    # 4. UPDATE (PUT/PATCH)
    # url: /projects/{pk}/update-project/
    @action(detail=True, methods=["PUT", "PATCH"], url_path="update-project")
    def update_project(self, request, pk=None):
        instance = self.get_object()
        # Pass partial=True if method is PATCH, else False
        partial = True
        serializer = self.get_serializer(
            instance, data=request.data, partial=partial, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()  # This calls the .update() method in your serializer
        return Response(serializer.data)

    # 5. DELETE (DELETE)
    # url: /projects/{pk}/delete-project/
    @action(detail=True, methods=["DELETE"], url_path="delete-project")
    def delete_project(self, request, pk=None):
        # Note: Serializers generally don't handle deletion, so this logic stays in the view
        instance = self.get_object()
        instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
