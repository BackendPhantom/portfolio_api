from django.conf import settings
from django.db import models
from django.db.models import ProtectedError
from django.db.models.signals import pre_delete
from django.dispatch import receiver

from core.models import TimestampedModel

class CategoryType(models.TextChoices):
    SOFT = "soft", "Soft Skill"
    TECHNICAL = "technical", "Technical Skill"


class SkillCategory(TimestampedModel):
    _TYPE_NAMES = {
        CategoryType.SOFT: "Soft Skills",
        CategoryType.TECHNICAL: "Technical Skills",
    }

    name = models.CharField(max_length=255, unique=True, editable=False)
    category_type = models.CharField(
        max_length=20,
        choices=CategoryType.choices,
        unique=True,
        db_index=True,
    )
    is_system = models.BooleanField(
        default=True,
        help_text="System categories cannot be modified or deleted.",
    )

    class Meta:
        verbose_name_plural = "Skill Categories"
        ordering = ["name"]

    def save(self, *args, **kwargs):
        # Auto-derive name from category_type so they never go out of sync.
        self.name = self._TYPE_NAMES[self.category_type]
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name

class SkillSubCategory(TimestampedModel):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="skill_subcategories"
    )
    name = models.CharField(max_length=255)
    category = models.ForeignKey(
        SkillCategory, related_name="subcategories", on_delete=models.PROTECT, limit_choices_to={"category_type": CategoryType.TECHNICAL}
    )

    class Meta:
        verbose_name="Skill Subcategory"
        verbose_name_plural = "Skill Subcategories"
        unique_together = ("user", "name", "category")
        indexes = [
            models.Index(fields=["user", "name"]),
            models.Index(fields=["user", "category"]),
        ]
        ordering = ["name"]
    
    def __str__(self):
        return f"{self.name} ({self.user})"
    


class Skill(TimestampedModel):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="skills"
    )
    # Protect the category from being deleted while any Skill refers to it.
    name = models.CharField(max_length=255)
    category = models.ForeignKey(SkillCategory, on_delete=models.PROTECT, db_index=True, editable=False, default=CategoryType.TECHNICAL)
    sub_category = models.ForeignKey(
        SkillSubCategory, related_name="skills", on_delete=models.PROTECT, null=True, blank=True
    )
    

    class Meta:
        ordering = ["category", "name"]
        unique_together = ("user", "category", "name", "sub_category")
        indexes = [
            models.Index(fields=["user", "category"]),
            models.Index(fields=["user", "name"]),
        ]

    def __str__(self):
        return self.name

    def __str__(self):
        return f"{self.name} [{self.category.name}]"

    def clean(self):
        from django.core.exceptions import ValidationError

        if self.category == CategoryType.TECHNICAL:
            if not self.sub_category_id:
                raise ValidationError(
                    {"sub_category": "Technical skills require a sub-category."}
                )
            
        elif self.category == CategoryType.SOFT:
            if self.sub_category_id:
                raise ValidationError(
                    {"sub_category": "Soft skills cannot have a sub-category."}
                )
            

    def delete(self, using=None, keep_parents=False):
        # Prevent deleting a Skill that is referenced by any Project via the M2M
        # relation `projects`.
        if self.category == CategoryType.TECHNICAL:
            linked = self.projects.all()  # reverse M2M from Project.tech_stack
            if linked.exists():
                raise ProtectedError(
                    "Cannot delete a technical skill that is still linked to one or more projects.",
                    linked,
                )
        return super().delete(using=using, keep_parents=keep_parents)


@receiver(pre_delete, sender=Skill)
def prevent_skill_delete_if_used(sender, instance, using, **kwargs):
    """
    Covers bulk ``QuerySet.delete()`` which bypasses ``Model.delete()``.
    Only blocks deletion for technical skills still linked to projects.
    """
    if instance.category == CategoryType.TECHNICAL:
        linked = instance.projects.all()
        if linked.exists():
            raise ProtectedError(
                "Cannot delete a technical skill that is still linked to one or more projects.",
                linked,
            )