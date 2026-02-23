from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import APIKey

User = get_user_model()


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Custom admin for the User model with all portfolio fields."""
    

    list_display = (
        "email",
        "full_name",
        "title",
        "is_available_for_hire",
        "is_active",
        "created_at",
    )
    list_filter = (
        "is_active",
        "is_staff",
        "is_superuser",
        "is_available_for_hire",
        "is_open_to_freelance",
        "is_profile_public",
        "email_verified",
    )
    search_fields = ("email", "first_name", "last_name", "title", "bio")
    ordering = ("-created_at",)

    # Fieldsets for the change user page
    fieldsets = (
        (None, {"fields": ("email", "password", "token_version")}),
        (
            "Personal Info",
            {
                "fields": (
                    "first_name",
                    "last_name",
                    "avatar",
                    "title",
                    "bio",
                    "location",
                    "date_of_birth",
                    "phone_number",
                   
                ),
                "classes": ("collapse",),
            },
        ),
        (
            "Links",
            {
                "fields": (
                    "website",
                    "github_url",
                    "linkedin_url",
                    "twitter_url",
                ),
                "classes": ("collapse",),
            },
        ),
        (
            "Professional",
            {
                "fields": (
                    "years_of_experience",
                    "is_available_for_hire",
                    "is_open_to_freelance",
                ),
                "classes": ("collapse",),
            },
        ),
        (
            "Settings",
            {
                "fields": (
                    "email_verified",
                    "is_profile_public",
                ),
                "classes": ("collapse",),
            },
        ),
        (
            "Permissions",
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                ),
                "classes": ("collapse",),
            },
        ),
        (
            "Important dates",
            {
                "fields": ("last_login", "date_joined", "created_at", "updated_at"),
                "classes": ("collapse",),
            },
        ),
    )

    # Fieldsets for the add user page
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "password1",
                    "password2",
                    "first_name",
                    "last_name",
                ),
            },
        ),
    )

    readonly_fields = ("created_at", "updated_at", "last_login", "date_joined")


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    """Admin for API Key management."""

    list_display = ("prefix", "name", "user", "is_active", "created_at", "last_used_at")
    list_filter = ("is_active",)
    search_fields = ("name", "prefix", "user__email")
    readonly_fields = ("prefix", "key_hash", "created_at", "last_used_at")
    raw_id_fields = ("user",)
