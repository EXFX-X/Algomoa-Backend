from django.contrib import admin
from django.urls import path,include
from . import views

urlpatterns = [
    # path('login/kakao', views.kakao_login, name = "kakao_login"),
    path('login', views.kakao_get_login),
    path('login/kakao', views.kakao_Token_Test1, name = "kakao_login"),
    # path('login/google', views.google_login),
    # path('accounts/',include('allauth.urls')),
    path('login/google', views.google_login, name='google_login'),
    path('accounts/google/login/callback/', views.google_callback, name='google_callback'),
    # path('accounts/google/login/finish/', views.GoogleLogin.as_view(), name='google_login_todjango'),
]
