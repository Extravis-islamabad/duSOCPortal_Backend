from django.urls import path

from integration.views import (
    IntegrationCreateAPIView,
    IntegrationListAPIView,
    IntegrationTypesView,
)

urlpatterns = [
    path(
        "get_integration_types/",
        IntegrationTypesView.as_view(),
        name="integration-types",
    ),
    path(
        "add_integration/",
        IntegrationCreateAPIView.as_view(),
        name="add-integration",
    ),
    path(
        "get_all_integrations/",
        IntegrationListAPIView.as_view(),
        name="get-all-integrations",
    ),
]
