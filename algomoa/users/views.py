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
from json import JSONDecodeError
from .models import *
from allauth.socialaccount.models import SocialAccount
from dj_rest_auth.registration.views import SocialLoginView
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from allauth.socialaccount.providers.google import views as google_view
from algomoa import my_settings

state = my_settings.STATE
BASE_URL = 'http://127.0.0.1:8000/'
GOOGLE_CALLBACK_URI = BASE_URL + 'accounts/google/login/callback/'


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
            user_id = kakao_id,
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
# 구글 로그인
def google_login(request):
    scope = "https://www.googleapis.com/auth/userinfo.email " + \
                "https://www.googleapis.com/auth/userinfo.profile"
    client_id = my_settings.SOCIAL_AUTH_GOOGLE_CLIENT_ID
    return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?client_id={client_id}&response_type=code&redirect_uri={GOOGLE_CALLBACK_URI}&scope={scope}")

def google_callback(request):
    client_id = my_settings.SOCIAL_AUTH_GOOGLE_CLIENT_ID
    client_secret = my_settings.SOCIAL_AUTH_GOOGLE_SECRET
    code = request.GET.get('code')

    # 1. 받은 코드로 구글에 access token 요청
    token_req = requests.post(f"https://oauth2.googleapis.com/token?client_id={client_id}&client_secret={client_secret}&code={code}&grant_type=authorization_code&redirect_uri={GOOGLE_CALLBACK_URI}&state={state}")

    ### 1-1. json으로 변환 & 에러 부분 파싱
    token_req_json = token_req.json()
    error = token_req_json.get("error")

    ### 1-2. 에러 발생 시 종료
    if error is not None:
        raise JSONDecodeError(error)

    ### 1-3. 성공 시 access_token 가져오기
    access_token = token_req_json.get('access_token')

    headers = {
        "Authorization": f"Bearer {access_token}",
    }

    user_info_response = requests.get(url=
        "https://www.googleapis.com/userinfo/v2/me",
        # params={
        #     'access_token': access_token
        # },
        headers=headers
    )

    print(user_info_response.json())
    user_profile = user_info_response.json()

    email = user_profile.get("email")
    name = user_profile.get("name")
    google_id = user_profile.get("id")
    # {'id': '100653528820403215784',
    # 'email': 'skm0626shinee@gmail.com',
    # 'verified_email': True,
    # 'name': 'KM S',
    # 'given_name': 'KM',
    # 'family_name': 'S',
    # 'picture': 'https://lh3.googleusercontent.com/a-/AFdZucroZ_wy8U_3_GTXqAEPRpkNmHkeLojf8cmt-CkHOg=s96-c',
    # 'locale': 'ko'}
    # DB 확인
    if not User.objects.filter(user_id = google_id).exists():
        user = User.objects.create(
            user_id = google_id,
            email = email,
            name = name,
            checked_social = True
        )
        # user.set_unusable_password()
        user.save()

    else:
        return JsonResponse({'message':'already exist'}, status=400)
    return JsonResponse({'message':'test'}, status=401)

    # if User.objects.filter(social_login_id = user['sub']).exists(): #기존에 가입했었는지 확인
    #         user_info           = User.objects.get(social_login_id=user['sub']) # 가입된 데이터를 변수에 저장
    #         encoded_jwt         = jwt.encode({'id': user["sub"]}, wef_key, algorithm='HS256') # jwt토큰 발행
    #         none_member_type    = 1
    #
    #         return JsonResponse({ # 프론트엔드에게 access token과 필요한 데이터 전달
    #             'access_token'  : encoded_jwt.decode('UTF-8'),
    #             'user_name'     : user['name'],
    #             'user_type'     : none_member_type,
    #             'user_pk'       : user_info.id
    #         }, status = 200)
    #     else:
    #         new_user_info = User( # 처음으로 소셜로그인을 했을 경우 회원으 정보를 저장(email이 없을 수도 있다 하여, 있으면 저장하고, 없으면 None으로 표기)
    #             social_login_id = user['sub'],
    #             name            = user['name'],
    #             social          = SocialPlatform.objects.get(platform ="google"),
    #             email           = user.get('email', None)
    #         )
    #         new_user_info.save() # DB에 저장
    #         encoded_jwt         = jwt.encode({'id': new_user_info.id}, wef_key, algorithm='HS256') # jwt토큰 발행
    #
    #         return JsonResponse({ # DB에 저장된 회원의 정보를 access token과 같이 프론트엔드에게 전달
    #         'access_token'      : encoded_jwt.decode('UTF-8'),
    #         'user_name'         : new_user_info.name,
    #         'user_type'         : none_member_type,
    #         'user_pk'           : new_user_info.id,
    #         }, status = 200)
    #################################################################

#     # 2. 가져온 access_token으로 이메일값을 구글에 요청
#     email_req = requests.get(f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={access_token}")
#     email_req_status = email_req.status_code
#
#     ### 2-1. 에러 발생 시 400 에러 반환
#     if email_req_status != 200:
#         return JsonResponse({'err_msg': 'failed to get email'}, status=status.HTTP_400_BAD_REQUEST)
#
#     ### 2-2. 성공 시 이메일 가져오기
#     email_req_json = email_req.json()
#     email = email_req_json.get('email')
#
#     # return JsonResponse({'access': access_token, 'email':email})
#
#     #################################################################
#
#     # 3. 전달받은 이메일, access_token, code를 바탕으로 회원가입/로그인
#     try:
#         # 전달받은 이메일로 등록된 유저가 있는지 탐색
#         user = User.objects.get(email=email)
#
#         # FK로 연결되어 있는 socialaccount 테이블에서 해당 이메일의 유저가 있는지 확인
#         social_user = SocialAccount.objects.get(user=user)
#
#         # 있는데 구글계정이 아니어도 에러
#         if social_user.provider != 'google':
#             return JsonResponse({'err_msg': 'no matching social type'}, status=status.HTTP_400_BAD_REQUEST)
#
#         # 이미 Google로 제대로 가입된 유저 => 로그인 & 해당 우저의 jwt 발급
#         data = {'access_token': access_token, 'code': code}
#         accept = requests.post(f"http://127.0.0.1:8000/accounts/google/login/finish/", data=data)
#         accept_status = accept.status_code
#
#         # 뭔가 중간에 문제가 생기면 에러
#         if accept_status != 200:
#             return JsonResponse({'err_msg': 'failed to signin'}, status=accept_status)
#
#         accept_json = accept.json()
#         accept_json.pop('user', None)
#         return JsonResponse(accept_json)
#
#     except User.DoesNotExist:
#         # 전달받은 이메일로 기존에 가입된 유저가 아예 없으면 => 새로 회원가입 & 해당 유저의 jwt 발급
#         data = {'access_token': access_token, 'code': code}
#         print("data:::::::",data)
#         accept = requests.post(f"http://127.0.0.1:8000/accounts/google/login/finish/", data=data)
#         accept_status = accept.status_code
#
#         # 뭔가 중간에 문제가 생기면 에러
#         if accept_status != 200:
#             return JsonResponse({'err_msg': 'failed to signup'}, status=accept_status)
#
#         accept_json = accept.json()
#         accept_json.pop('user', None)
#         return JsonResponse(accept_json)
#     except SocialAccount.DoesNotExist:
#     	# User는 있는데 SocialAccount가 없을 때 (=일반회원으로 가입된 이메일일때)
#         return JsonResponse({'err_msg': 'email exists but not social user'}, status=status.HTTP_400_BAD_REQUEST)
#
# class GoogleLogin(SocialLoginView):
#     adapter_class = google_view.GoogleOAuth2Adapter
#     callback_url = GOOGLE_CALLBACK_URI
#     client_class = OAuth2Client
# @api_view(['GET'])
# @permission_classes([AllowAny, ])
# def google_login(request):
#     return render(request, 'google_login.html')
