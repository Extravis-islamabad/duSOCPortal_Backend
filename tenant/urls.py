from django.urls import path

from tenant.views import (
    DashboardView,
    DuCortexSOARTenantsListView,
    DuIbmQradarTenantsListView,
    DuITSMTenantsListView,
    EventCollectorsListAPIView,
    GetTenantAssetsList,
    IncidentDetailView,
    IncidentsView,
    OwnerDistributionView,
    PermissionChoicesAPIView,
    SeverityDistributionView,
    SLAStatusView,
    TenantAPIView,
    TenantCortexSOARIncidentsAPIView,
    TenantITSMTicketsView,
    TestView,
    TypeDistributionView,
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
    path("get_itsm_tickets/", TenantITSMTicketsView.as_view(), name="get-itsm-tickets"),
    path(
        "get_cortex_soar_incidents/",
        TenantCortexSOARIncidentsAPIView.as_view(),
        name="get-cortex-soar-incidents",
    ),
    path(
        "api/dashboard/severity-distribution/<int:tenant_id>/",
        SeverityDistributionView.as_view(),
        name="severity-distribution",
    ),
    path(
        "api/dashboard/type-distribution/<int:tenant_id>/",
        TypeDistributionView.as_view(),
        name="type-distribution",
    ),
    path(
        "api/dashboard/sla-status/<int:tenant_id>/",
        SLAStatusView.as_view(),
        name="sla-status",
    ),
    path(
        "api/dashboard/owner-distribution/<int:tenant_id>/",
        OwnerDistributionView.as_view(),
        name="owner-distribution",
    ),
    path("api/dashboard/<int:tenant_id>/", DashboardView.as_view(), name="dashboard"),
    path("api/incidents/<int:tenant_id>/", IncidentsView.as_view(), name="incidents"),
    path(
        "api/incidents/<int:incident_id>/<int:tenant_id>/",
        IncidentDetailView.as_view(),
        name="incident-detail",
    ),
    path("test/", TestView.as_view(), name="test"),
]
