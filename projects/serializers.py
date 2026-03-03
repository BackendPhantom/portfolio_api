from django.db import transaction
from rest_framework import serializers

from skills.models import CategoryType, Skill, SkillCategory, SkillSubCategory

from .models import Project


class TechStackSerializer(serializers.Serializer):
    """Input serializer for technical skills on a project.

    ``sub_category`` is the name of a user-owned SkillSubCategory (e.g.
    'Backend', 'DevOps'). It is auto-created if it does not yet exist.
    ``category`` is always forced to ``technical`` server-side.
    """

    name = serializers.CharField(max_length=255)
    sub_category = serializers.CharField(max_length=255)


class SkillOutputSerializer(serializers.ModelSerializer):
    """Read serializer for technical skills displayed on a project."""

    sub_category = serializers.CharField(source="sub_category.name", read_only=True)

    class Meta:
        model = Skill
        fields = ["id", "name", "sub_category"]


class ProjectSerializer(serializers.ModelSerializer):
    id = serializers.HyperlinkedIdentityField(
        view_name="projects-project-details", lookup_field="pk"
    )
    tech_stack = TechStackSerializer(many=True, write_only=True)
    tech_stack_display = SkillOutputSerializer(
        source="tech_stack", many=True, read_only=True
    )

    class Meta:
        model = Project
        fields = "__all__"
        # User is read_only because we set it automatically in the create() method below
        read_only_fields = ("id", "user", "slug")

    def _resolve_skills(self, user, tech_stack_data):
        """
        For each item in tech_stack_data:
          1. Fetch the system-level 'Technical Skills' SkillCategory.
          2. get_or_create the user's SkillSubCategory by name.
          3. get_or_create the Skill under that sub_category.

        Returns a list of Skill instances ready to be set on the M2M.
        """
        technical_category, _ = SkillCategory.objects.get_or_create(
            category_type=CategoryType.TECHNICAL,
            defaults={"is_system": True},
        )
        skills = []
        for item in tech_stack_data:
            skill_name = item["name"].strip().lower()
            sub_cat_name = item["sub_category"].strip().lower()

            sub_category, _ = SkillSubCategory.objects.get_or_create(
                user=user,
                name=sub_cat_name,
                defaults={"category": technical_category},
            )

            skill, _ = Skill.objects.get_or_create(
                user=user,
                category=technical_category,
                name=skill_name,
                sub_category=sub_category,
            )
            skills.append(skill)

        return skills

    def create(self, validated_data):
        """Create a project and attach its technical skills via the M2M."""
        user = self.context["request"].user
        tech_stack_data = validated_data.pop("tech_stack")
        with transaction.atomic():
            project = Project.objects.create(user=user, **validated_data)
            project.tech_stack.set(self._resolve_skills(user, tech_stack_data))
        return project

    def update(self, instance, validated_data):
        """Update project fields and replace the tech stack if provided."""
        tech_stack_data = validated_data.pop("tech_stack", None)
        user = self.context["request"].user
        with transaction.atomic():
            for attr, value in validated_data.items():
                setattr(instance, attr, value)
            instance.save()
            if tech_stack_data is not None:
                instance.tech_stack.set(self._resolve_skills(user, tech_stack_data))
        return instance

    def to_representation(self, instance):
        data = super().to_representation(instance)
        for key, value in data.items():
            if isinstance(value, str):
                data[key] = value.lower()
        return data
