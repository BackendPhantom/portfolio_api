from rest_framework import serializers

from .models import Skill, SkillCategory, SkillSubCategory, CategoryType
from django.db import transaction


class SkillCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = SkillCategory
        fields = ["id", "name", "category_type"]
        read_only_fields = fields


class SkillSerializer(serializers.ModelSerializer):
    sub_category = serializers.CharField(source="sub_category.name", read_only=True)

    class Meta:
        model = Skill
        fields = (
            "id",
            "name",
            "category",
            "sub_category",
        )
        read_only_fields = ("id", "category", "sub_category")

    def create(self, validated_data):
        soft_category, _ = SkillCategory.objects.get_or_create(category_type=CategoryType.SOFT,
            defaults={"is_system": True},)
        
        with transaction.atomic():
            skill = Skill.objects.create(
                user=self.context["request"].user, category=soft_category, **validated_data)
        return skill

    def to_representation(self, instance):
        """Customize the output to include the category name and sub-category name."""
        representation = super().to_representation(instance)
        representation["category"] = instance.category.name
        representation["sub_category"] = instance.sub_category.name if instance.sub_category else None
        for key, value in representation.items():
            if isinstance(value, str):
                representation[key] = value.lower()
        return representation