import time

from loguru import logger
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from authentication.permissions import IsAdminUser, IsTenant
from tenant.models import (
    DuIbmQradarTenants,
    Tenant,
    TenantPermissionChoices,
    TenantRole,
)
from tenant.serializers import DuIbmQradarTenantsSerializer, TenantRoleSerializer


class PermissionChoicesAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        """
        Retrieves the permission choices.

        Returns a JSON response with the following data on success:
        - permissions: list of objects (Permission choice details)

        Returns HTTP 200 status code on success, or HTTP 500 for any other server error.
        """
        try:
            # Get all PermissionChoices as a list of dictionaries
            permissions = [
                {"id": choice.value, "text": choice.label}
                for choice in TenantPermissionChoices
            ]

            return Response(
                {
                    "permissions": permissions,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class TenantAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request, tenant_id=None):
        start = time.time()
        try:
            # Get the authenticated user
            user = request.user
            tenant = Tenant.objects.get(tenant=user)
            roles = TenantRole.objects.filter(tenant=tenant).prefetch_related(
                "role_permissions"
            )
            serializer = TenantRoleSerializer(roles, many=True)

            logger.info(
                f"TenantAPIView.get for tenant {tenant.id} took {time.time() - start} seconds"
            )
            return Response(
                {
                    "tenant_id": tenant.id,
                    "tenant_username": tenant.tenant.username
                    if tenant.tenant
                    else "Unnamed Tenant",
                    "roles": serializer.data,
                },
                status=status.HTTP_200_OK,
            )

        except Tenant.DoesNotExist:
            logger.error(
                f"Tenant not found: tenant_id={tenant_id or 'user_id=' + str(user.id)}"
            )
            return Response(
                {"error": "Tenant not found"}, status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error in TenantAPIView.get: {str(e)}")
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class DuIbmQradarTenantsListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        tenants = DuIbmQradarTenants.objects.all()  # Retrieve all records
        serializer = DuIbmQradarTenantsSerializer(tenants, many=True)
        return Response(serializer.data)
