import uuid

from django.conf import settings
from django.db import models

from core.models import TimestampedModel
from core.utils import generate_unique_slug
from skills.models import Skill


class Project(TimestampedModel):
    """Portfolio project with soft-delete, unique slug, and choice enums."""

    class ProjectType(models.TextChoices):
        PERSONAL = "personal", "Personal"
        CLIENT = "client", "Client"
        OPEN_SOURCE = "open_source", "Open Source"
        ACADEMIC = "academic", "Academic"

    class Status(models.TextChoices):
        PLANNING = "planning", "Planning"
        IN_PROGRESS = "in_progress", "In Progress"
        COMPLETED = "completed", "Completed"
        ARCHIVED = "archived", "Archived"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="projects"
    )

    title = models.CharField(max_length=255)
    # slug = models.SlugField(max_length=280, unique=True, blank=True)
    description = models.TextField()

    # project_type = models.CharField(
    #     max_length=20,
    #     choices=ProjectType.choices,
    #     default=ProjectType.PERSONAL,
    #     db_index=True,
    # )
    # status = models.CharField(
    #     max_length=20,
    #     choices=Status.choices,
    #     default=Status.PLANNING,
    #     db_index=True,
    # )
    # featured = models.BooleanField(default=False, db_index=True)

    # Links
    live_url = models.URLField(blank=True, null=True)
    github_url = models.URLField(blank=True, null=True)

    # Tech stack
    tech_stack = models.ManyToManyField(Skill, related_name="projects", blank=True)
    # Ordering

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "-created_at"]),
            models.Index(fields=["title"]),
            # models.Index(fields=["status", "featured"]),
        ]

    def __str__(self):
        return self.title

    # def save(self, *args, **kwargs):
    #     if not self.slug:
    #         self.slug = generate_unique_slug(Project, self.title, self)
    #     super().save(*args, **kwargs)
