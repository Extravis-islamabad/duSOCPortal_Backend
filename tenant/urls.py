from django.urls import path

from tenant.views import (
    DuCortexSOARTenantsListView,
    DuIbmQradarTenantsListView,
    DuITSMTenantsListView,
    EventCollectorsListAPIView,
    GetTenantAssetsList,
    PermissionChoicesAPIView,
    TenantAPIView,
    TestView,
)

urlpatterns = [
    path("permissions/", PermissionChoicesAPIView.as_view(), name="permission_choices"),
    path("tenant-permissions/", TenantAPIView.as_view(), name="tenant-permissions"),
    path(
        "get_qradar_tenants/",
        DuIbmQradarTenantsListView.as_view(),
        name="get-qradar-tenants",
    ),
    path(
        "get_event_collecors/",
        EventCollectorsListAPIView.as_view(),
        name="get-event-collectors",
    ),
    path(
        "get_itsm_tenants/",
        DuITSMTenantsListView.as_view(),
        name="get-itsm-tenants",
    ),
    path(
        "get_cortex_soar_tenants/",
        DuCortexSOARTenantsListView.as_view(),
        name="get-cortex-soar-tenants",
    ),
    path("get_tenant_assets/", GetTenantAssetsList.as_view(), name="get-tenant-assets"),
]
