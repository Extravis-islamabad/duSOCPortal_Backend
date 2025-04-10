from django.urls import path

from tenantadmin.views import (
    AllTenantsAPIView,
    TenantCreateAPIView,
    TenantDeleteAPIView,
    TenantDetailAPIView,
    TenantUpdateAPIView,
)

urlpatterns = [
    path("create_tenant/", TenantCreateAPIView.as_view(), name="tenant-create"),
    path(
        "update_tenant/<int:tenant_id>/",
        TenantUpdateAPIView.as_view(),
        name="tenant-update",
    ),
    path(
        "tenant_detail/<int:tenant_id>/",
        TenantDetailAPIView.as_view(),
        name="tenant-detail",
    ),
    path("get_all_tenants/", AllTenantsAPIView.as_view(), name="all-tenants"),
    path(
        "delete_tenant/<int:tenant_id>/",
        TenantDeleteAPIView.as_view(),
        name="tenant-delete",
    ),
]
