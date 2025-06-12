from django.urls import path

from integration.views import (
    CredentialTypesListAPIView,
    GetAllIntegrationsAPIView,
    GetIntegrationInstanceListView,
    IntegrationCreateAPIView,
    IntegrationTypesView,
    TestIntegrationAPIView,
    TestIntegrationConnectionAPIView,
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
        TestIntegrationAPIView.as_view(),
        name="test-integration",
    ),
    path(
        "test_connection/<int:integration_id>/",
        TestIntegrationConnectionAPIView.as_view(),
        name="test-integration-connection",
    ),
    path("get_integration_instances/", GetIntegrationInstanceListView.as_view()),
]
