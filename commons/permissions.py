from django.contrib.auth import get_user_model
from rest_framework.permissions import SAFE_METHODS, BasePermission

User = get_user_model()


class IsSelf(BasePermission):
    """
    Only allow users to access their own user object.
    Superusers cannot bypass this.
    """

    def has_object_permission(self, request, view, obj):
        if isinstance(obj, User):
            return obj == request.user  # only self
        # fallback for related models
        return getattr(obj, "user", None) == request.user


class IsAuthenticatedAndOwner(BasePermission):
    """
    Allows access only to authenticated users who own the object.
    """

    def has_permission(self, request, view):
        # Step 1: User must be authenticated
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        # Step 2: Object must belong to the user
        return obj.user == request.user


class ProjectPermission(BasePermission):
    def has_permission(self, request, view):
        if view.action == "create":
            return request.user.is_authenticated
        return True

    def has_object_permission(self, request, view, obj):
        if view.action in ["update", "partial_update", "destroy"]:
            return obj.user == request.user
        return True


class IsOwnerOrReadOnly(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True
        return obj.user == request.user
