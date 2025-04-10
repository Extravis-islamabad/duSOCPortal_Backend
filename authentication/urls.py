from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    PermissionChoicesAPIView,
    UserCreateAPIView,
    UserDetailsAPIView,
    UserLoginAPIView,
)

urlpatterns = [
    path("create_user/", UserCreateAPIView.as_view(), name="user-create"),
    path("login/", UserLoginAPIView.as_view(), name="user-login"),
    path("user_details/", UserDetailsAPIView.as_view(), name="user_details"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("permissions/", PermissionChoicesAPIView.as_view(), name="permission_choices"),
]
