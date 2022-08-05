import os
from urllib import response
import requests
from xml.dom.minidom import Attr
from django.http import JsonResponse
from django.shortcuts import render, redirect
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from algomoa.my_settings import client_id
from . import models

@api_view(['GET'])
@permission_classes([AllowAny, ])
def kakao_get_login(request):
    redirect_uri = "http://127.0.0.1:8000/login/kakao"
    url= "https://kauth.kakao.com/oauth/authorize?response_type=code&client_id={0}&redirect_uri={1}".format(
        client_id, redirect_uri)
    result = redirect(url)
    #print(result)
    return redirect(url)#result # 동의하기를 누르면 인가 코드가 발급된다. # 내가 미리 정해준 redirect명으로 code가 발급 그러니깐 이 밑에 함수는 그 url에 대한 내용을 써야겟지



@api_view(['GET'])
@permission_classes([AllowAny, ])
def kakao_Token_Test1(request):
    code = request.query_params['code'] # url에 있는 code 명 가져오기
    redirect_uri = "http://127.0.0.1:8000/login/kakao"

    token_response = requests.get(
        f"https://kauth.kakao.com/oauth/token?grant_type=authorization_code&client_id={client_id}&redirect_uri={redirect_uri}&code={code}"
    )

    token_json = token_response.json() # 여기에 access token 있음
    user_profile_url = "https://kapi.kakao.com/v2/user/me"
    access_token = token_json['access_token']
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Contet-type": "application/x-www-form-urlencoded;charset=utf-8"
    }

    user_profile_response = requests.get(url=user_profile_url, headers=headers)
    print(user_profile_response.json())

    user_profile = user_profile_response.json()
    email = user_profile.get("kakao_account").get("email")
    name = user_profile.get("properties").get("nickname")
    kakao_id = user_profile.get("id")


    # DB 확인
    if not models.User.objects.filter(kakao_id = kakao_id).exists():
        user = models.User.objects.create(
            kakao_id = kakao_id,
            email = email,
            name = name,
            checked_social = True
        )
        # user.set_unusable_password()
        user.save()

    else:
        return JsonResponse({'message':'already exist'}, status=400)
    return JsonResponse({'message':'test'}, status=401)

'''
# get
def kakao_Token_Test2(request):
    try:
        kakao_token = request.headers.get("Authorization")

        if kakao_token == None:
            return JsonResponse({'message':'TOKEN FAIL'}, status=401)


    except AttributeError:
        return JsonResponse({'message':'FAIL'}, status=400)
'''
