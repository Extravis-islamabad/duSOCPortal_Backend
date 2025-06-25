from django.urls import path

from tenant.views import (
    AlertDetailView,
    AlertListView,
    AllIncidentsView,
    DashboardView,
    DuCortexSOARTenantsListView,
    DuIbmQradarTenantsListView,
    DuITSMTenantsListView,
    EPSCountValuesByDomainAPIView,
    EventCollectorsListAPIView,
    GetTenantAssetsList,
    IncidentDetailView,
    IncidentReportView,
    IncidentSummaryView,
    IncidentsView,
    OffenseCategoriesAPIView,
    OffenseDetailsByTenantAPIView,
    OffenseDetailsWithFlowsAndAssetsAPIView,
    OffenseDetailsWithFlowsAndAssetsDBIDAPIView,
    OffenseStatsAPIView,
    OwnerDistributionView,
    PermissionChoicesAPIView,
    RecentIncidentsView,
    SeverityDistributionView,
    SLAComplianceView,
    SLAIncidentsView,
    SLASeverityIncidentsView,
    SLASeverityMetricsView,
    SLAStatusView,
    TenantAPIView,
    TenantCortexSOARIncidentsAPIView,
    TenantITSMTicketsView,
    TestView,
    TopLogSourcesAPIView,
    TotalAssetsByTenantAPIView,
    TotalTicketsByTenantAPIView,
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
        "api/dashboard/severity-distribution/",
        SeverityDistributionView.as_view(),
        name="severity-distribution",
    ),
    path(
        "api/dashboard/type-distribution/",
        TypeDistributionView.as_view(),
        name="type-distribution",
    ),
    path(
        "api/dashboard/sla-status/",
        SLAStatusView.as_view(),
        name="sla-status",
    ),
    path(
        "api/dashboard/owner-distribution/",
        OwnerDistributionView.as_view(),
        name="owner-distribution",
    ),
    path("api/dashboard/", DashboardView.as_view(), name="dashboard"),
    path("api/incidents/", IncidentsView.as_view(), name="incidents"),
    path(
        "api/incidents/<int:incident_id>/",
        IncidentDetailView.as_view(),
        name="incident-detail",
    ),
    path("api/offense-stats/", OffenseStatsAPIView.as_view(), name="offense-stats"),
    path(
        "api/offenses-by-tenant-details/",
        OffenseDetailsByTenantAPIView.as_view(),
        name="offense-details-by-tenant",
    ),
    path(
        "api/offense-details/<int:offense_id>/",
        OffenseDetailsWithFlowsAndAssetsAPIView.as_view(),
        name="offense-details-with-flows-and-assets",
    ),
    path(
        "api/offense-details_db_id/<int:offense_id>/",
        OffenseDetailsWithFlowsAndAssetsDBIDAPIView.as_view(),
        name="offense-details-with-flows-and-assets",
    ),
    path(
        "api/offense-categories/",
        OffenseCategoriesAPIView.as_view(),
        name="offense-categories",
    ),
    path(
        "api/top-log-sources/", TopLogSourcesAPIView.as_view(), name="top-log-sources"
    ),
    path(
        "api/total-assets-by-tenant/",
        TotalAssetsByTenantAPIView.as_view(),
        name="total-assets-by-tenant",
    ),
    path(
        "api/total-tickets-by-tenant/",
        TotalTicketsByTenantAPIView.as_view(),
        name="total-tickets-by-tenant",
    ),
    path("api/eps/", EPSCountValuesByDomainAPIView.as_view(), name="tenant"),
    path(
        "get_threat_intelligence/",
        AlertListView.as_view(),
        name="get-threat-intelligence",
    ),
    #     path("test/", TestView.as_view(), name="test"),
    # ]
    path("test/", TestView.as_view(), name="test"),
    path(
        "api/recent-incidents/",
        RecentIncidentsView.as_view(),
        name="recent-incidents",
    ),
    path(
        "alerts/<str:alert_id>/details/",
        AlertDetailView.as_view(),
        name="alert-details",
    ),
    path("api/all-incidents/", AllIncidentsView.as_view(), name="all-incidents"),
    path(
        "api/incident-summary-cards/",
        IncidentSummaryView.as_view(),
        name="incident-summary",
    ),
    path(
        "api/sla-incidents/",
        SLAIncidentsView.as_view(),
        name="sla-incidents",
    ),
    path(
        "api/sla-compliance-widgets-dashboard/",
        SLAComplianceView.as_view(),
        name="sla-compliance",  # Name for the new route
    ),
    path(
        "api/sla-severity-incidents-graph/",
        SLASeverityIncidentsView.as_view(),
        name="sla-severity-incidents-graph",
    ),
    path(
        "api/sla-severity-metrics-dashboard/",
        SLASeverityMetricsView.as_view(),
        name="sla-severity-metrics",
    ),
    path("api/incident-report/", IncidentReportView.as_view(), name="incident-report"),
]
