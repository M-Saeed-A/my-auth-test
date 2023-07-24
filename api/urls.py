from django.urls import path
from . import views
urlpatterns = [
    path('re-access/', views.TokenRefreshAPIView.as_view())
]