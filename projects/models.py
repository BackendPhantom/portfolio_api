import uuid

from django.conf import settings  # Best practice to refer to User
from django.db import models

from skills.models import Skill

# Create your models here.


class Project(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="projects"
    )

    title = models.CharField(max_length=255)
    description = models.TextField()

    # Links
    live_url = models.URLField(blank=True, null=True)
    github_url = models.URLField(blank=True, null=True)

    # Sophisticated Data (Stored as JSON)
    # Example: ["Python", "Django", "React"]
    tech_stack = models.ManyToManyField(Skill, related_name="projects")

    # Auto-fetched Data (We will build the scraper for this next week)
    # stars_count = models.IntegerField(default=0)
    # forks_count = models.IntegerField(default=0)
    # last_commit_date = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]  # Newest projects first
        indexes = [
            # Composite index: Get user's projects ordered by date
            models.Index(fields=["user", "-created_at"]),
            # For title search
            models.Index(fields=["title"]),
        ]

    def __str__(self):
        return self.title
