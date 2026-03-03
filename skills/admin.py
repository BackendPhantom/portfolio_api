from django.contrib import admin

from .models import Skill, SkillCategory, SkillSubCategory

admin.site.register(Skill)
admin.site.register(SkillCategory)
admin.site.register(SkillSubCategory)

# Register your models here.
