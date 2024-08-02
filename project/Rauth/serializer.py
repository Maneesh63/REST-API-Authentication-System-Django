from rest_framework import serializers
from rest_framework.serializers import ModelSerializer
from . models import *
from rest_framework.authtoken.models import Token

class CustomUserSerializer(serializers.ModelSerializer):

    class Meta:
        token = serializers.CharField(max_length=255, read_only=True)
        model=CustomUser
        fields=['username','email','password']

    def create(self, validated_data):
         user = CustomUser.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
         )
         token, created = Token.objects.get_or_create(user=user)
         user.token = token.key
         return user