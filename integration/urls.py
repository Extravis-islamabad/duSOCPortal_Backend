from django.urls import path

from integration.views import IntegrationTypesView

urlpatterns = [
    path(
        "get_integration_types/",
        IntegrationTypesView.as_view(),
        name="integration-types",
    ),
]
