from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    LDAPGroupListView,
    LDAPGroupUsersView,
    LDAPUsersAPIView,
    TenantProfileUpdateAPIView,
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
        TenantProfileUpdateAPIView.as_view(),
        name="upload-profile-picture",
    ),
    path("get_ldap_users/", LDAPUsersAPIView.as_view(), name="get-ldap-users"),
    path("api/ldap/groups/", LDAPGroupListView.as_view(), name="ldap-groups"),
    path(
        "api/ldap/groups/<str:group_name>/users/",
        LDAPGroupUsersView.as_view(),
        name="ldap-group-users",
    ),
]
