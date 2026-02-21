from django.db import transaction
from rest_framework import serializers

from skills.models import Skill, SkillCategory

from .models import Project


class TechStackSerializer(serializers.Serializer):
    # This serializer is for demonstration purposes if you were to
    # accept tech stack as a simple list of strings in the request.
    # For ManyToManyField, you'd typically use PrimaryKeyRelatedField or SlugRelatedField.
    name = serializers.CharField(max_length=100)
    category = serializers.CharField(max_length=100)


class SkillOutputSerializer(serializers.ModelSerializer):
    category = serializers.CharField(source="category.name")

    class Meta:
        model = Skill
        fields = ["name", "category"]


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

    def create(self, validated_data):
        """
        Handles the creation logic ('C' in CRUD).
        We access the user from the context passed by the view.
        """
        user = self.context.get("request").user
        tech_stack_data = validated_data.pop("tech_stack")
        with transaction.atomic():
            project = Project.objects.create(user=user, **validated_data)
            skills = []
            for tech_stack in tech_stack_data:
                skill_name = tech_stack.get("name").strip().lower()
                category_name = tech_stack.get("category").strip().lower()

                category, _ = SkillCategory.objects.get_or_create(
                    user=user,
                    name=category_name,
                    defaults={"name": category_name},
                )

                skill, _ = Skill.objects.get_or_create(
                    user=user,
                    category=category,
                    name=skill_name,
                    defaults={"name": skill_name},
                )

                skills.append(skill)

            project.tech_stack.set(skills)

        return project

    def update(self, instance, validated_data):
        """
        Handles the update logic ('U' in CRUD).
        """
        # You can add specific business logic here if needed

        tech_stack_data = validated_data.pop("tech_stack")
        user = self.context.get("request").user
        with transaction.atomic():
            for attr, value in validated_data.items():
                setattr(instance, attr, value)
            instance.save()
            if tech_stack_data is not None:
                skills = []
                for tech_stack in tech_stack_data:
                    skill_name = tech_stack.get("name").strip().lower()
                    category_name = tech_stack.get("category").strip().lower()

                    category, _ = SkillCategory.objects.get_or_create(
                        user=user, name=category_name
                    )
                    skill, _ = Skill.objects.get_or_create(
                        user=user, category=category, name=skill_name
                    )
                    skills.append(skill)
                instance.tech_stack.set(skills)
        return instance

    def to_representation(self, instance):
        data = super().to_representation(instance)
        for key, value in data.items():
            if isinstance(value, str):
                data[key] = value.lower()
        return data
