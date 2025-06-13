from django.urls import path

from tenantadmin.views import (
    AllTenantsAPIView,
    NonActiveTenantsAPIView,
    SyncCortexSOARDataAPIView,
    SyncIBMQradarDataAPIView,
    SyncITSMDataAPIView,
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
        "get_deleted_tenants/",
        NonActiveTenantsAPIView.as_view(),
        name="deleted-tenants",
    ),
    path(
        "delete_tenant/<int:tenant_id>/",
        TenantDeleteAPIView.as_view(),
        name="tenant-delete",
    ),
    path("sync_qradar/", SyncIBMQradarDataAPIView.as_view(), name="sync-ibm-qradar"),
    path("sync_soar/", SyncCortexSOARDataAPIView.as_view(), name="sync-cortex-soar"),
    path("sync_itsm/", SyncITSMDataAPIView.as_view(), name="sync-itsm"),
]
