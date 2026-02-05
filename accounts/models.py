import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """
    Custom User model for Developer Portfolio.
    Uses email as the primary identifier and UUID as primary key.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    token_version = models.PositiveIntegerField(default=0)

    # -------------------------------------------------------------------------
    # Profile Information
    # -------------------------------------------------------------------------
    first_name = models.CharField(max_length=50, blank=True)
    last_name = models.CharField(max_length=50, blank=True)
    avatar = models.URLField(
        blank=True, help_text="URL to profile picture (can be from social provider)"
    )
    title = models.CharField(
        max_length=100,
        blank=True,
        help_text="Professional title, e.g., 'Full Stack Developer'",
    )
    bio = models.TextField(blank=True, help_text="Short biography or about section")
    location = models.CharField(
        max_length=100, blank=True, help_text="City, Country or Remote"
    )
    website = models.URLField(blank=True, help_text="Personal website or portfolio URL")

    # -------------------------------------------------------------------------
    # Social Links
    # -------------------------------------------------------------------------
    github_url = models.URLField(blank=True)
    linkedin_url = models.URLField(blank=True)
    twitter_url = models.URLField(blank=True)

    # -------------------------------------------------------------------------
    # Professional Details
    # -------------------------------------------------------------------------
    years_of_experience = models.PositiveSmallIntegerField(
        null=True, blank=True, help_text="Years of professional experience"
    )
    is_available_for_hire = models.BooleanField(
        default=False, help_text="Open to job opportunities"
    )
    is_open_to_freelance = models.BooleanField(
        default=False, help_text="Available for freelance work"
    )

    # -------------------------------------------------------------------------
    # Email Verification & Settings
    # -------------------------------------------------------------------------
    email_verified = models.BooleanField(
        default=False, help_text="Whether email has been verified"
    )
    is_profile_public = models.BooleanField(
        default=True, help_text="Whether profile is visible to public"
    )

    # -------------------------------------------------------------------------
    # Timestamps
    # -------------------------------------------------------------------------
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "User"
        verbose_name_plural = "Users"

    def __str__(self):
        return self.email

    @property
    def full_name(self):
        """Returns the user's full name or email if not set."""
        if self.first_name or self.last_name:
            return f"{self.first_name} {self.last_name}".strip()
        return self.email.split("@")[0]

    @property
    def has_complete_profile(self):
        """Check if user has filled out essential profile fields."""
        return all([self.first_name, self.last_name, self.title, self.bio])
