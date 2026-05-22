"""
URL configuration for sockportal__backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

schema_view = get_schema_view(
    openapi.Info(
        title="duSOC Portal Backend APIs",
        default_version="v1",
        description="Comprehensive API documentation for the duSOC Portal Backend system, including Authentication, Tenant Management, Integration, and LDAP services.",
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
    authentication_classes=[],  # No authentication for accessing docs
)

urlpatterns = (
    [
        path("admin-super/", admin.site.urls),
        path("auth/", include("authentication.urls")),
        path("tenant/", include("tenant.urls")),
        path("admin/", include("tenantadmin.urls")),
        path("integration/", include("integration.urls")),
        # API Documentation URLs
        path(
            "docs/",
            schema_view.with_ui("swagger", cache_timeout=0),
            name="schema-swagger-ui",
        ),
        path(
            "redoc/",
            schema_view.with_ui("redoc", cache_timeout=0),
            name="schema-redoc",
        ),
        path(
            "swagger.json",
            schema_view.without_ui(cache_timeout=0),
            name="schema-json",
        ),
        path(
            "swagger.yaml",
            schema_view.without_ui(cache_timeout=0),
            name="schema-yaml",
        ),
    ]
    + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
)
