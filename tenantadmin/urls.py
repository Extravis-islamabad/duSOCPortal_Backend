from django.urls import path

from tenantadmin.views import (
    APIVersionAPIView,
    AssetsSummaryAPIView,
    CheckCompanyNameExistView,
    CompanyTenantSettingsUpdateAPIView,
    CustomerEPSAPIView,
    DeleteTenantByCompanyView,
    DistinctCompaniesAPIView,
    IncidentPrioritySummaryAPIView,
    NonActiveTenantsAPIView,
    ReactivateTenantUsersAPIView,
    SlaLevelsAPIView,
    SyncCortexSOARDataAPIView,
    SyncIBMQradarDataAPIView,
    SyncITSMDataAPIView,
    TenantCreateAPIView,
    TenantDetailAPIView,
    TenantInactiveView,
    TenantsByCompanyAPIView,
    VolumeTypeChoicesAPIView,
)

urlpatterns = [
    path("create_tenant/", TenantCreateAPIView.as_view(), name="tenant-create"),
    path(
        "update_tenant/<int:company_id>/",
        CompanyTenantSettingsUpdateAPIView.as_view(),
        name="tenant-update",
    ),
    path(
        "tenant_detail/<int:company_id>/",
        TenantDetailAPIView.as_view(),
        name="tenant-detail",
    ),
    # path("get_all_tenants/", AllTenantsAPIView.as_view(), name="all-tenants"),
    path("companies/", DistinctCompaniesAPIView.as_view(), name="distinct-companies"),
    path(
        "tenants/by-company/<int:company_id>/",
        TenantsByCompanyAPIView.as_view(),
        name="tenants-by-company",
    ),
    path(
        "get_deleted_tenants/",
        NonActiveTenantsAPIView.as_view(),
        name="deleted-tenants",
    ),
    path(
        "delete_tenant/<int:company_id>/",
        DeleteTenantByCompanyView.as_view(),
        name="tenant-delete",
    ),
    path(
        "reactivate_tenant/<int:company_id>/",
        ReactivateTenantUsersAPIView.as_view(),
        name="reactivate-tenant",
    ),
    path(
        "inactivate_tenant/<int:company_id>/",
        TenantInactiveView.as_view(),
        name="inactivate_tenant",
    ),
    path("sync_qradar/", SyncIBMQradarDataAPIView.as_view(), name="sync-ibm-qradar"),
    path("sync_soar/", SyncCortexSOARDataAPIView.as_view(), name="sync-cortex-soar"),
    path("sync_itsm/", SyncITSMDataAPIView.as_view(), name="sync-itsm"),
    path("volume-types/", VolumeTypeChoicesAPIView.as_view(), name="volume-types"),
    path("sla_levels/", SlaLevelsAPIView.as_view(), name="sla_levels"),
    path("customer_eps/", CustomerEPSAPIView.as_view(), name="customer-eps"),
    path("check_company/", CheckCompanyNameExistView.as_view(), name="check-company"),
    path("assets_summary/", AssetsSummaryAPIView.as_view(), name="assets-summary"),
    path(
        "incident_priority_summary/",
        IncidentPrioritySummaryAPIView.as_view(),
        name="incident-priority-summary",
    ),
    path("api-version/", APIVersionAPIView.as_view(), name="api-version"),
]
