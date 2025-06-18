from django.urls import path

from tenantadmin.views import (
    AllTenantsAPIView,
    DistinctCompaniesAPIView,
    NonActiveTenantsAPIView,
    ReactivateTenantUsersAPIView,
    SlaLevelsAPIView,
    SyncCortexSOARDataAPIView,
    SyncIBMQradarDataAPIView,
    SyncITSMDataAPIView,
    TenantCreateAPIView,
    TenantDeleteAPIView,
    TenantDetailAPIView,
    TenantsByCompanyAPIView,
    TenantUpdateAPIView,
    VolumeTypeChoicesAPIView,
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
    path("companies/", DistinctCompaniesAPIView.as_view(), name="distinct-companies"),
    path(
        "tenants/by-company/",
        TenantsByCompanyAPIView.as_view(),
        name="tenants-by-company",
    ),
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
    path(
        "reactivate_tenant/<int:tenant_id>/",
        ReactivateTenantUsersAPIView.as_view(),
        name="reactivate-tenant",
    ),
    path("sync_qradar/", SyncIBMQradarDataAPIView.as_view(), name="sync-ibm-qradar"),
    path("sync_soar/", SyncCortexSOARDataAPIView.as_view(), name="sync-cortex-soar"),
    path("sync_itsm/", SyncITSMDataAPIView.as_view(), name="sync-itsm"),
    path("volume-types/", VolumeTypeChoicesAPIView.as_view(), name="volume-types"),
    path("sla_levels/", SlaLevelsAPIView.as_view(), name="sla_levels"),
]
