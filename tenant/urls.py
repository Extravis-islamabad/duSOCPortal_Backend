from django.urls import path

from tenant.views import PermissionChoicesAPIView

urlpatterns = [
    path("permissions/", PermissionChoicesAPIView.as_view(), name="permission_choices"),
]
