from django.urls import path

from integration.views import (
    CredentialTypesListAPIView,
    GetAllIntegrationsAPIView,
    IntegrationCreateAPIView,
    IntegrationTypesView,
    TestIntegrationView,
    UpdateCredentialView,
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
        "get_types/",
        CredentialTypesListAPIView.as_view(),
        name="get-types",
    ),
    path(
        "get_all_integrations/",
        GetAllIntegrationsAPIView.as_view(),
        name="get-all-integrations",
    ),
    path(
        "credentials/<int:pk>/update/",
        UpdateCredentialView.as_view(),
        name="update-credential",
    ),
    path(
        "test_integration/",
        TestIntegrationView.as_view(),
        name="test-integration",
    ),
]
