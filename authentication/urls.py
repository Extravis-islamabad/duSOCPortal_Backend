from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    ProfilePictureUploadView,
    UserCreateAPIView,
    UserDetailsAPIView,
    UserLoginAPIView,
    UserLogoutAPIView,
)

urlpatterns = [
    path("create_user/", UserCreateAPIView.as_view(), name="user-create"),
    path("login/", UserLoginAPIView.as_view(), name="user-login"),
    path("logout/", UserLogoutAPIView.as_view(), name="user-logout"),
    path("user_details/", UserDetailsAPIView.as_view(), name="user_details"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path(
        "upload-profile-picture/",
        ProfilePictureUploadView.as_view(),
        name="upload-profile-picture",
    ),
]
