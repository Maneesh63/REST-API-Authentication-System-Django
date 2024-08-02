from django.shortcuts import render,HttpResponse,redirect

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate
from .serializer import *
import hashlib
from django.utils.crypto import get_random_string
from datetime import datetime, timedelta
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.urls import reverse
import logging
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated

logger = logging.getLogger(__name__)

def home(request):

    return HttpResponse('HOME PAGE')

class RegisterView(APIView):
   permission_classes = [AllowAny]

   def post(self, request):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(serializer.data,status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [AllowAny]  # 
    def post(self,request):

        email=request.data.get('email')

        password=request.data.get('password')

        if not email or not password:
            return Response({'error': 'Please provide both username and password.'},
                            status=status.HTTP_400_BAD_REQUEST)
        
        user=authenticate(email=email,password=password)

        if user is not None:
             
            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key,'email':email}, status=status.HTTP_200_OK)
        else:
            # Authentication failed
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()


OTP_EXPIRATION_MINUTES = 5 

class Sendotp(APIView):
    permission_classes = [AllowAny]  # 
    def post(self,request,**kwargs):

        email=request.data.get('email')

        try:

           user=  CustomUser.objects.get(email=email)
        
        except CustomUser.DoesNotExist:

            return Response({"error": "User with this email does not exist."}, status=status.HTTP_400_BAD_REQUEST)
        #generating hash
        otp=get_random_string(length=6,allowed_chars='0123456789')
        
        #hashing the OTP with salt(unique id: email)
        otp_hash=hash_otp(otp)

        expiration_time = datetime.now() + timedelta(minutes=OTP_EXPIRATION_MINUTES)

        OTPModel.objects.update_or_create(user=user,defaults={'otp_hash':otp_hash,'expiration_time': expiration_time})

        send_mail(
            'Your OTP Code',
            f'Your OTP code is {otp}',
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )
        reset_url = request.build_absolute_uri(reverse('verify_otp'))
        return Response({"message": "OTP sent to your email."}, status=status.HTTP_200_OK,headers={'Location': reset_url})
   


class Verifyotp(APIView):

    permission_classes = [AllowAny]

    def post(self, request):
        otp = request.data.get('otp')
        new_password = request.data.get('new_password')

        if not otp:
            return Response({"error": "OTP is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        if not new_password:
            return Response({"error": "New password is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            otp_hash = hash_otp(otp)
            otp_record = OTPModel.objects.get(otp_hash=otp_hash)
        except OTPModel.DoesNotExist:
            return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

        #Check if OTP has expired
        if timezone.now() > otp_record.expiration_time:
            return Response({"error": "OTP has expired."}, status=status.HTTP_400_BAD_REQUEST)

        user = otp_record.user  # Retrieve the user associated with the OTP

        # Set the new password for the user and save it
        user.set_password(new_password)
        user.save()

        # Invalidate the OTP
        otp_record.delete()

        # Return success message
        return Response({"message": "Password reset successfully."}, status=status.HTTP_200_OK)