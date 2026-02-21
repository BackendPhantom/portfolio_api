from django.conf import settings
from django.db import models
from django.db.models.signals import pre_delete
from django.db.models import ProtectedError
from django.dispatch import receiver

from core.models import TimestampedModel


class SkillCategory(TimestampedModel):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="skill_category",
    )
    name = models.CharField(max_length=255)

    class Meta:
        verbose_name_plural = "Skill Categories"
        ordering = ["name"]
        unique_together = ("user", "name")
        indexes = [
            models.Index(fields=["user", "name"]),
        ]

    def __str__(self):
        return self.name


class Skill(TimestampedModel):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="skills"
    )
    # Protect the category from being deleted while any Skill refers to it.
    category = models.ForeignKey(
        SkillCategory, related_name="items", on_delete=models.PROTECT
    )
    name = models.CharField(max_length=255)

    class Meta:
        ordering = ["name"]
        unique_together = ("user", "category", "name")
        indexes = [
            models.Index(fields=["user", "category"]),
            models.Index(fields=["user", "name"]),
        ]

    def __str__(self):
        return self.name

    def delete(self, using=None, keep_parents=False):
        # Prevent deleting a Skill that is referenced by any Project via the M2M
        # relation `projects`.
        if hasattr(self, "projects") and self.projects.exists():
            raise ProtectedError(
                "Cannot delete skill while it is associated with one or more projects.",
                self.projects.all(),
            )
        return super().delete(using=using, keep_parents=keep_parents)


@receiver(pre_delete, sender=Skill)
def prevent_skill_delete_if_used(sender, instance, using, **kwargs):
    # This signal handler covers cases where `QuerySet.delete()` is used
    # (which bypasses `Model.delete`). It raises a `ProtectedError` if the
    # skill is linked to any projects.
    if hasattr(instance, "projects") and instance.projects.exists():
        raise ProtectedError(
            "Cannot delete skill while it is associated with one or more projects.",
            instance.projects.all(),
        )
