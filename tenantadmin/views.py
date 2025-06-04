# authentication/views.py

from loguru import logger
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from authentication.permissions import IsAdminUser
from common.constants import PaginationConstants
from tenant.cortex_soar_tasks import sync_soar_data
from tenant.ibm_qradar_tasks import sync_ibm_qradar_data
from tenant.itsm_tasks import sync_itsm
from tenant.models import Tenant
from tenant.serializers import (
    TenantCreateSerializer,
    TenantDetailSerializer,
    TenantUpdateSerializer,
)
from tenant.threat_intelligence_tasks import (
    sync_threat_intel,
    sync_threat_intel_for_tenants,
)


class TenantCreateAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def post(self, request):
        serializer = TenantCreateSerializer(
            data=request.data, context={"request": request}
        )
        if serializer.is_valid():
            tenants = serializer.save()
            sync_threat_intel.delay()
            sync_threat_intel_for_tenants.delay()
            return Response(
                {
                    "message": "Tenants created successfully",
                    "tenants": [
                        {
                            "tenant_id": tenant.id,
                        }
                        for tenant in tenants
                    ],
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class TenantCreateAPIView(APIView):
#     authentication_classes = [JWTAuthentication]
#     permission_classes = [IsAdminUser]

#     def post(self, request):
#         serializer = TenantCreateSerializer(
#             data=request.data, context={"request": request}
#         )
#         if serializer.is_valid():
#             tenant = serializer.save()
#             return Response(
#                 {
#                     "message": "Tenant created successfully",
#                     "tenant_id": tenant.id,
#                     "user_id": tenant.tenant.id,
#                     "role_id": tenant.roles.first().id,
#                 },
#                 status=status.HTTP_201_CREATED,
#             )
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class TenantUpdateAPIView(APIView):
#     authentication_classes = [JWTAuthentication]
#     permission_classes = [IsAdminUser]

#     def patch(self, request, tenant_id):
#         logger.info(
#             f"Tenant update request by user: {request.user.username} for tenant_id: {tenant_id}"
#         )
#         try:
#             tenant = Tenant.objects.get(id=tenant_id, created_by=request.user)
#         except Tenant.DoesNotExist:
#             logger.warning(
#                 f"Tenant with id {tenant_id} not found or not owned by {request.user.username}"
#             )
#             return Response(
#                 {
#                     "error": "Tenant not found or you do not have permission to update it."
#                 },
#                 status=status.HTTP_404_NOT_FOUND,
#             )

#         serializer = TenantUpdateSerializer(tenant, data=request.data, partial=True)

#         if serializer.is_valid():
#             try:
#                 updated_tenant = serializer.save()
#                 logger.success(
#                     f"Tenant updated: {updated_tenant.tenant.username} (ID: {updated_tenant.id})"
#                 )
#                 # Use TenantDetailSerializer for full details
#                 detail_serializer = TenantDetailSerializer(updated_tenant)
#                 return Response(
#                     {
#                         "tenant": detail_serializer.data,
#                     },
#                     status=status.HTTP_200_OK,
#                 )
#             except Exception as e:
#                 logger.error(f"Error updating tenant: {str(e)}")
#                 return Response(
#                     {"error": f"An error occurred: {str(e)}"},
#                     status=status.HTTP_500_INTERNAL_SERVER_ERROR,
#                 )

#         logger.warning(f"Tenant update failed: {serializer.errors}")
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TenantUpdateAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def put(self, request, tenant_id):
        try:
            tenant = Tenant.objects.get(id=tenant_id, created_by=request.user)
        except Tenant.DoesNotExist:
            return Response(
                {"error": "Tenant not found"}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = TenantUpdateSerializer(
            tenant, data=request.data, partial=True, context={"request": request}
        )
        if serializer.is_valid():
            tenant = serializer.save()
            return Response({"message": "Tenant updated successfully"})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TenantDetailAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request, tenant_id):
        logger.info(
            f"Tenant detail request by user: {request.user.username} for tenant_id: {tenant_id}"
        )
        try:
            # Only allow the creator to view their tenant
            tenant = Tenant.objects.get(id=tenant_id, created_by=request.user)
        except Tenant.DoesNotExist:
            logger.warning(
                f"Tenant with id {tenant_id} not found or not owned by {request.user.username}"
            )
            return Response(
                {"error": "Tenant not found or you do not have permission to view it."},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = TenantDetailSerializer(tenant)
        logger.success(
            f"Tenant details retrieved: {tenant.tenant.username} (ID: {tenant.id})"
        )
        return Response(serializer.data, status=status.HTTP_200_OK)


class AllTenantsAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        logger.info(f"All tenants request by user: {request.user.username}")
        tenants = Tenant.objects.filter(created_by=request.user)

        paginator = PageNumberPagination()
        paginator.page_size = PaginationConstants.PAGE_SIZE

        paginated_tenants = paginator.paginate_queryset(tenants, request)
        serializer = TenantDetailSerializer(paginated_tenants, many=True)

        logger.success(
            f"Retrieved {tenants.count()} tenants for user: {request.user.username}"
        )

        return paginator.get_paginated_response(serializer.data)


class TenantDeleteAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def delete(self, request, tenant_id):
        logger.info(
            f"Tenant delete request by user: {request.user.username} for tenant_id: {tenant_id}"
        )
        try:
            # Only allow the creator to delete their tenant
            tenant = Tenant.objects.get(id=tenant_id, created_by=request.user)
        except Tenant.DoesNotExist:
            logger.warning(
                f"Tenant with id {tenant_id} not found or not owned by {request.user.username}"
            )
            return Response(
                {
                    "error": "Tenant not found or you do not have permission to delete it."
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        tenant_username = tenant.tenant.username if tenant.tenant else "Unnamed Tenant"
        tenant.delete()
        logger.success(f"Tenant deleted: {tenant_username} (ID: {tenant_id})")
        return Response(
            {"message": "Tenant deleted successfully."}, status=status.HTTP_200_OK
        )


class SyncIBMQradarDataAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        sync_ibm_qradar_data.delay()
        return Response({"message": "Sync process for IBM QRadar data started."})


class SyncCortexSOARDataAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        sync_soar_data.delay()
        return Response({"message": "Sync process for Cotex SOAR data started."})


class SyncITSMDataAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        sync_itsm.delay()
        return Response({"message": "Sync process for ITSM SOAR data started."})
