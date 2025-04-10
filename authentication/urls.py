from django.urls import path

from .views import UserCreateAPIView, UserLoginAPIView

urlpatterns = [
    path("create_user/", UserCreateAPIView.as_view(), name="user-create"),
    path("login/", UserLoginAPIView.as_view(), name="user-login"),
]
