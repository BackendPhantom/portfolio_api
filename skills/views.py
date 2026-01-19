from django.shortcuts import render
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import Skill, SkillCategory
from .serializers import SkillCategorySerializer, SkillSerializer
from rest_framework.exceptions import MethodNotAllowed
from commons.permissions import IsAuthenticatedAndOwner


# Create your views here.
class SkillCategoryViewSet(viewsets.ModelViewSet):
    queryset = SkillCategory.objects.all()
    serializer_class = SkillCategorySerializer
    permission_classes = [IsAuthenticatedAndOwner]



    def create(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)

    def update(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)
    
    def retrieve(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)
    
    def partial_update(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)
    
    def destroy(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)



class SkillViewSet(viewsets.ModelViewSet):
    queryset = Skill.objects.all()
    serializer_class = SkillSerializer
    permission_classes = [IsAuthenticatedAndOwner]


    def create(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)

    def update(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)
    
    def retrieve(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)
    
    def partial_update(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)
    
    def destroy(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)
