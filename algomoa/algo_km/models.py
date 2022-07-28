from django.db import models


# Create your models here.
class Member(models.Model):
    name = models.CharField(max_length=200)
    mail = models.CharField(max_length=200)
    age = models.IntegerField(default=0)

#class User(AbstractUser):
    #
    # """ Custom User model """
    #
    # LOGIN_EMAIL = "email"
    # LOGIN_GITHUB = "github"
    # LOGIN_KAKAO = "kakao"
    #
    # LOGIN_CHOICES = (
    #     (LOGIN_EMAIL, "Email"),
    #     (LOGIN_GITHUB, "Github"),
    #     (LOGIN_KAKAO, "Kakao"),
    # )
    #
    # login_method = models.CharField(
    #     max_length=6, choices=LOGIN_CHOICES, default=LOGIN_EMAIL
    # )
