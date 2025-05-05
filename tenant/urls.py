from django.urls import path

from tenant.views import (
    DuIbmQradarTenantsListView,
    PermissionChoicesAPIView,
    TenantAPIView,
)

urlpatterns = [
    path("permissions/", PermissionChoicesAPIView.as_view(), name="permission_choices"),
    path("tenant-permissions/", TenantAPIView.as_view(), name="tenant-permissions"),
    path(
        "get_qradar_tenants/",
        DuIbmQradarTenantsListView.as_view(),
        name="get-qradar-tenants",
    ),
]
