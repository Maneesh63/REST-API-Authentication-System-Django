from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
 
#if the password not in hashed format in Database,authentication method "check_password" doesnot work, so ensure the password 
class EmailBackend(BaseBackend):

    def authenticate(self, request,username=None, email=None, password=None, **kwargs):
        UserModel=get_user_model()

        try:
            user=UserModel.objects.get(email=email)

            if user.check_password(password):
                return user
        except UserModel.DoesNotExist:

            return None