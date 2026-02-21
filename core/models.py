"""
Core abstract models shared across all apps.

- ``TimestampedModel``  — adds ``created_at`` / ``updated_at``
- ``SoftDeleteModel``   — adds ``deleted_at`` with manager filtering
- ``ActivityLog``       — lightweight audit trail
"""

from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.utils import timezone


# =========================================================================
# Timestamped Base
# =========================================================================
class TimestampedModel(models.Model):
    """Abstract model that adds ``created_at`` and ``updated_at``."""

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


# =========================================================================
# Soft Delete
# =========================================================================
class SoftDeleteQuerySet(models.QuerySet):
    """QuerySet that supports soft-delete operations."""

    def delete(self):
        """Soft-delete all matched rows."""
        return self.update(deleted_at=timezone.now())

    def hard_delete(self):
        """Permanently delete all matched rows."""
        return super().delete()

    def alive(self):
        return self.filter(deleted_at__isnull=True)

    def dead(self):
        return self.filter(deleted_at__isnull=False)


class SoftDeleteManager(models.Manager):
    """Default manager that hides soft-deleted objects."""

    def get_queryset(self):
        return SoftDeleteQuerySet(self.model, using=self._db).alive()

    def all_with_deleted(self):
        return SoftDeleteQuerySet(self.model, using=self._db)

    def deleted_only(self):
        return SoftDeleteQuerySet(self.model, using=self._db).dead()


class SoftDeleteModel(TimestampedModel):
    """
    Abstract model providing soft-delete behaviour.

    - Default ``objects`` manager hides deleted rows.
    - Use ``all_objects`` to include deleted rows.
    - Call ``instance.delete()`` to soft-delete.
    - Call ``instance.hard_delete()`` to permanently remove.
    - Call ``instance.restore()`` to un-delete.
    """

    deleted_at = models.DateTimeField(null=True, blank=True, db_index=True)

    objects = SoftDeleteManager()
    all_objects = SoftDeleteQuerySet.as_manager()

    def delete(self, using=None, keep_parents=False):
        self.deleted_at = timezone.now()
        self.save(update_fields=["deleted_at"])

    def hard_delete(self, using=None, keep_parents=False):
        super().delete(using=using, keep_parents=keep_parents)

    def restore(self):
        self.deleted_at = None
        self.save(update_fields=["deleted_at"])

    class Meta:
        abstract = True


# =========================================================================
# Activity Log (Audit Trail)
# =========================================================================
class ActivityLog(models.Model):
    """Lightweight audit trail for dashboard "recent activity" feed."""

    class Action(models.TextChoices):
        CREATED = "created", "Created"
        UPDATED = "updated", "Updated"
        DELETED = "deleted", "Deleted"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="activity_logs",
    )
    action = models.CharField(max_length=10, choices=Action.choices)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.CharField(max_length=255)
    content_object = GenericForeignKey("content_type", "object_id")
    object_repr = models.CharField(max_length=200)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["user", "-timestamp"]),
        ]

    def __str__(self):
        return f"{self.user} {self.action} {self.object_repr}"
