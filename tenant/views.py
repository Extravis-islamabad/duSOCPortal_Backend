# authentication/views.py

from loguru import logger
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from tenant.models import TenantPermissionChoices
from tenant.serializers import TenantCreateSerializer


class PermissionChoicesAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

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


class TenantCreateAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        logger.info(f"Tenant creation request by user: {request.user.username}")
        serializer = TenantCreateSerializer(
            data=request.data, context={"request": request}
        )

        if serializer.is_valid():
            try:
                tenant = serializer.save()
                logger.success(
                    f"Tenant created: {tenant.name or 'Unnamed Tenant'} (ID: {tenant.id})"
                )
                return Response(
                    {
                        "message": "Tenant created successfully",
                        "tenant_id": tenant.id,
                        "name": tenant.name,
                        "created_by": tenant.created_by.username,
                    },
                    status=status.HTTP_201_CREATED,
                )
            except Exception as e:
                logger.error(f"Error creating tenant: {str(e)}")
                return Response(
                    {"error": f"An error occurred: {str(e)}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        logger.warning(f"Tenant creation failed: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
