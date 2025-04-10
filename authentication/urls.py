from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import UserCreateAPIView, UserLoginAPIView

urlpatterns = [
    path("create_user/", UserCreateAPIView.as_view(), name="user-create"),
    path("login/", UserLoginAPIView.as_view(), name="user-login"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
]
