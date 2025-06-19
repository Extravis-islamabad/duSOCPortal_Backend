# authentication/views.py
from django.db.models import Count
from loguru import logger
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from authentication.models import User
from authentication.permissions import IsAdminUser
from common.constants import PaginationConstants
from tenant.cortex_soar_tasks import sync_soar_data
from tenant.ibm_qradar_tasks import sync_ibm_qradar_data
from tenant.itsm_tasks import sync_itsm
from tenant.models import SlaLevelChoices, Tenant, VolumeTypeChoices
from tenant.serializers import (
    AllTenantDetailSerializer,
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


class TenantUpdateAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def put(self, request, tenant_id):
        try:
            tenant = Tenant.objects.get(id=tenant_id, created_by=request.user)
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found"}, status=404)
        company_name = tenant.tenant.company_name

        serializer = TenantUpdateSerializer(
            tenant, data=request.data, partial=True, context={"request": request}
        )
        related_tenants = Tenant.objects.filter(tenant__company_name=company_name)
        data = [{"tenant_id": t.id} for t in related_tenants]

        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Tenant updated successfully", "tenants": data},
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=400)


class TenantInactiveView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def post(self, request):
        company_name = request.data.get("company_name")

        if not company_name:
            return Response({"error": "Company name is required."}, status=400)

        users = User.objects.filter(company_name__iexact=company_name)

        if not users.exists():
            return Response(
                {"error": "No users found for the given company name."}, status=404
            )

        users.update(is_active=False)

        return Response(
            {"message": f"Users under company '{company_name}' have been deactivated."},
            status=200,
        )


class DeleteTenantByCompanyView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def delete(self, request):
        company_name = request.data.get("company_name")

        if not company_name:
            return Response({"error": "Company name is required."}, status=400)

        tenants = Tenant.objects.filter(tenant__company_name__iexact=company_name)

        if not tenants.exists():
            return Response(
                {"error": "No tenant found for the given company name."}, status=404
            )

        # Delete all associated users
        user_deleted_count, _ = User.objects.filter(
            company_name__iexact=company_name
        ).delete()

        # Delete all related tenants
        tenant_deleted_count, _ = tenants.delete()

        return Response(
            {"message": "Deleted tenant(s)  user(s) under company."},
            status=status.HTTP_200_OK,
        )


class ReactivateTenantUsersAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def post(self, request):
        company_name = request.data.get("company_name")

        if not company_name:
            return Response({"error": "Company name is required."}, status=400)

        users = User.objects.filter(company_name__iexact=company_name)
        if not users.exists():
            return Response(
                {"error": "No users found for the given company name."}, status=404
            )

        users.update(is_active=True)

        return Response(
            {
                "message": f"All users under company '{company_name}' have been reactivated."
            },
            status=200,
        )


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

        serializer = TenantDetailSerializer(tenant, context={"request": request})
        logger.success(
            f"Tenant details retrieved: {tenant.tenant.username} (ID: {tenant.id})"
        )
        return Response(serializer.data, status=status.HTTP_200_OK)


class AllTenantsAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        logger.info(f"All tenants request by user: {request.user.username}")
        tenants = Tenant.objects.filter(
            created_by=request.user, tenant__is_active=True, tenant__is_deleted=False
        ).order_by("-created_at")

        paginator = PageNumberPagination()
        paginator.page_size = PaginationConstants.PAGE_SIZE

        paginated_tenants = paginator.paginate_queryset(tenants, request)
        serializer = AllTenantDetailSerializer(paginated_tenants, many=True)

        logger.success(
            f"Retrieved {tenants.count()} tenants for user: {request.user.username}"
        )

        return paginator.get_paginated_response(serializer.data)


class TenantsByCompanyAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        company_name = request.query_params.get("company_name")

        if not company_name:
            return Response(
                {"error": "company_name is required as a query parameter."}, status=400
            )

        logger.info(
            f"Tenants by company '{company_name}' requested by user: {request.user.username}"
        )

        tenants = Tenant.objects.filter(
            created_by=request.user,
            tenant__is_active=True,
            tenant__is_deleted=False,
            tenant__company_name__iexact=company_name,
        ).order_by("-created_at")

        paginator = PageNumberPagination()
        paginator.page_size = PaginationConstants.PAGE_SIZE

        paginated_tenants = paginator.paginate_queryset(tenants, request)
        serializer = AllTenantDetailSerializer(paginated_tenants, many=True)

        logger.success(
            f"Retrieved {tenants.count()} tenants for company: {company_name}"
        )

        return paginator.get_paginated_response(serializer.data)


class DistinctCompaniesAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        companies = (
            Tenant.objects.filter(
                created_by=request.user,
                tenant__is_active=True,
                tenant__is_deleted=False,
                tenant__company_name__isnull=False,
            )
            .values("tenant__company_name")
            .annotate(tenant_count=Count("id"))
            .order_by("tenant__company_name")
        )

        # Format the response
        result = [
            {
                "name": entry["tenant__company_name"],
                "tenant_count": entry["tenant_count"],
            }
            for entry in companies
            if entry["tenant__company_name"]
        ]

        return Response({"companies": result}, status=200)


class NonActiveTenantsAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        logger.info(f"All tenants request by user: {request.user.username}")
        tenants = Tenant.objects.filter(
            created_by=request.user, tenant__is_active=False, tenant__is_deleted=True
        ).order_by("-created_at")

        paginator = PageNumberPagination()
        paginator.page_size = PaginationConstants.PAGE_SIZE

        paginated_tenants = paginator.paginate_queryset(tenants, request)
        serializer = AllTenantDetailSerializer(paginated_tenants, many=True)

        logger.success(
            f"Retrieved {tenants.count()} tenants for user: {request.user.username}"
        )

        return paginator.get_paginated_response(serializer.data)


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


class VolumeTypeChoicesAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        choices = [
            {"id": choice.value, "label": choice.label} for choice in VolumeTypeChoices
        ]
        return Response(choices, status=status.HTTP_200_OK)


class SlaLevelsAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        return Response(
            [{"value": level.value, "label": level.label} for level in SlaLevelChoices]
        )
