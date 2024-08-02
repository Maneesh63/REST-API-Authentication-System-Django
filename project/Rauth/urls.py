from django.urls import path
from . views import *

urlpatterns=[
   
   path('',home,name='home'),

   path('register/',RegisterView.as_view(),name='register'),

   path('login/', LoginView.as_view(), name='login'),

   path('sendotp/',Sendotp.as_view(), name='send_otp'),

   path('verifyotp/',Verifyotp.as_view(),name='verify_otp'),

]