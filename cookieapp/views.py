from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework import status
from .serializers import LoginSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from django.conf import settings

# from rest_framework.renderers import TemplateHTMLRenderer
# from django.utils.timezone import timedelta
# from django.utils import timezone
# from django.middleware import csrf

User = get_user_model()


def get_token_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token)
    }


class LoginView(APIView):
    # renderer_classes = [TemplateHTMLRenderer]
    serializer_class = LoginSerializer

    def post(self, request: Request):
        serializer = LoginSerializer(data=request.data)
        response = Response()
        if serializer.is_valid():
            user = authenticate(username=serializer.validated_data['username'],
                                password=serializer.validated_data['password'])
            if user is not None:
                if user.is_active:
                    tokens = get_token_for_user(user)
                    response.set_cookie(
                        key='refresh_token',
                        value=tokens['refresh'],
                        expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
                        httponly=True,
                        samesite='Lax'
                    )
                    response.set_cookie(
                        key='access_token',
                        value=tokens['access'],
                        expires=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                        httponly=True,
                        samesite='Lax'
                    )
                    # csrf.get_token(request)
                    response.data = {
                        "success": "Login successfully",
                        'data': tokens
                    }
                    return response
                else:
                    return Response({
                        "Not Active": "this account is not active"
                    }, status.HTTP_404_NOT_FOUND)
            else:
                return Response({
                    "Invalid": "Invalid username or password"
                }, status.HTTP_404_NOT_FOUND)


        else:
            return Response(serializer.errors, status.HTTP_400_BAD_REQUEST)
