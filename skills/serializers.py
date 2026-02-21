from rest_framework import serializers

from .models import Skill, SkillCategory


class SkillCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = SkillCategory
        fields = (
            "id",
            "name",
        )


class SkillSerializer(serializers.ModelSerializer):
    category = serializers.CharField(source="category.name")

    class Meta:
        model = Skill
        fields = (
            "id",
            "name",
            "category",
        )
