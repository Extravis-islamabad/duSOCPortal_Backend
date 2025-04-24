from django.urls import path

from tenant.views import PermissionChoicesAPIView, TenantAPIView

urlpatterns = [
    path("permissions/", PermissionChoicesAPIView.as_view(), name="permission_choices"),
    path("tenant-permissions/", TenantAPIView.as_view(), name="tenant-permissions"),
]
