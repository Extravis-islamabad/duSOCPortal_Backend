from django.urls import path

from integration.views import GetIBMQradarTenants, IntegrationTypesView

urlpatterns = [
    path(
        "get_integration_types/",
        IntegrationTypesView.as_view(),
        name="integration-types",
    ),
    path(
        "get_ibm_qradar_tenants/",
        GetIBMQradarTenants.as_view(),
        name="get-ibm-qradar-tenants",
    ),
]
