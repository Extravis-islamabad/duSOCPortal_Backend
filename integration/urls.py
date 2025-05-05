from django.urls import path

from integration.views import DuIbmQradarTenantsListView, IntegrationTypesView

urlpatterns = [
    path(
        "get_integration_types/",
        IntegrationTypesView.as_view(),
        name="integration-types",
    ),
    path(
        "get_ibm_qradar_tenants/",
        DuIbmQradarTenantsListView.as_view(),
        name="get-ibm-qradar-tenants",
    ),
]
