from django.urls import path

from tenant.views import PermissionChoicesAPIView, TenantCreateAPIView

urlpatterns = [
    path("permissions/", PermissionChoicesAPIView.as_view(), name="permission_choices"),
    path("create_tenant/", TenantCreateAPIView.as_view(), name="tenant-create"),
]
