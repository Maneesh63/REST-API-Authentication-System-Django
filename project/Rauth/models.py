from django.db import models
from django.contrib.auth.models import BaseUserManager,AbstractBaseUser,PermissionsMixin

#whle custom authentication "Customeusermanager" express the behaviour of credentials being saved
class CustomuserManager(BaseUserManager):
  
  def create_user(self,username,email,password=None,**kwargs):
     
     if not email:
        raise ValueError('Email Must Be Given')
     
     email=self.normalize_email(email)
     user=self.model(username=username,email=email,**kwargs)
     user.set_password(password)#for password hashing (if not password stored as hash form in database, call the set_password in views.py while accessing the password)
     user.save(using=self._db)
     return user
  
  #passing the arguments to superuser to ensure that superuser aslo have the same fields as user
  def create_superuser(self,username,email,password=None,**kwargs):
     
     kwargs.setdefault('is_staff',True)

     kwargs.setdefault('is_superuser',True)

     return self.create_user(username,email,password,**kwargs)


class CustomUser(AbstractBaseUser,PermissionsMixin):

    username=models.CharField(max_length=300,null=False)

    email=models.EmailField(null=False,unique=True)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    date=models.DateTimeField(auto_now_add=True,null=True)

    objects=CustomuserManager()

    USERNAME_FIELD = 'email'


    def __str__(self):
        return self.username


class OTPModel(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    otp_hash = models.CharField(max_length=64)
    expiration_time = models.DateTimeField()
