from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
import jwt
from rest_framework import exceptions
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

class IsLoggedIn(APIView):
    def post(self, request: Request):

        if request.auth:
            return Response({
                "message": "You Logged In"
            })
        else:
            return Response({
                "message": "access token is missing or invalid"
            }, status.HTTP_401_UNAUTHORIZED)


class TokenRefreshAPIView(APIView):
    def post(self, request: Request):
        response = Response()
        refresh_token = request.COOKIES.get('refresh_token')
        User = get_user_model()
        if refresh_token is None:
            raise exceptions.AuthenticationFailed("Authentication credentials were not provided.")
        try:
            payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=['HS256'])

        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed(
                "expired refresh token, please login again"
            )

        user = User.objects.filter(id=payload.get('user_id')).first()

        if user is None:
            raise exceptions.AuthenticationFailed('user not found')
        if not user.is_active:
            raise exceptions.AuthenticationFailed("user is inactive")

        refresh = RefreshToken.for_user(user)
        response.set_cookie(
            key='access_token',
            value=refresh.access_token,
            expires=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
            httponly=True,
            samesite='Lax'
        )
        return response
