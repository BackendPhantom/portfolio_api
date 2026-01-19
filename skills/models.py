from django.db import models
from django.conf import settings


# Create your models here.
class SkillCategory(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="skill_category",
    )
    name = models.CharField(max_length=255)

    class Meta:
        verbose_name_plural = "Skill Categories"
        unique_together = ("user", "name")

    def __str__(self):
        return self.name


class Skill(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="skills"
    )
    category = models.ForeignKey(
        SkillCategory, related_name="items", on_delete=models.PROTECT
    )
    name = models.CharField(max_length=255)

    class Meta:
        unique_together = ("user", "category", "name")

    def __str__(self):
        return self.name
