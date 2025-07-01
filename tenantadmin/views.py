# authentication/views.py
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
from tenant.models import (
    Company,
    CustomerEPS,
    SlaLevelChoices,
    Tenant,
    VolumeTypeChoices,
)
from tenant.serializers import (  # TenantUpdateSerializer,
    AllTenantDetailSerializer,
    CompanyTenantUpdateSerializer,
    CustomerEPSSerializer,
    TenantCreateSerializer,
    TenantDetailSerializer,
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
            company = serializer.save()
            sync_threat_intel.delay()
            sync_threat_intel_for_tenants.delay()
            return Response(
                {
                    "message": "Tenants created successfully",
                    "company_name": company.company_name,
                    "company_id": company.id,
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CompanyTenantSettingsUpdateAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def put(self, request, company_id):
        try:
            company = Company.objects.get(id=company_id, created_by=request.user)
        except Company.DoesNotExist:
            return Response({"error": "Company not found or unauthorized."}, status=404)

        serializer = CompanyTenantUpdateSerializer(
            company, data=request.data, context={"request": request, "company": company}
        )
        if serializer.is_valid():
            serializer.save()
            logger.success(
                f"Company settings and tenant sync completed for company_id={company_id}"
            )
            return Response(
                {"message": "Company settings updated successfully."}, status=200
            )
        else:
            logger.warning(
                f"Validation failed for company update - {serializer.errors}"
            )
            return Response(serializer.errors, status=400)


class TenantInactiveView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def post(self, request, company_id):
        try:
            company = Company.objects.get(id=company_id, created_by=request.user)
        except Exception:
            return Response(
                {"error": "Company with the given ID does not exist."},
                status=404,
            )

        # Get all tenant users under this company
        tenant_users = User.objects.filter(
            id__in=Tenant.objects.filter(
                company=company, created_by=request.user
            ).values_list("tenant__id", flat=True),
            is_active=True,
            is_deleted=False,
        )

        if not tenant_users.exists():
            return Response(
                {"error": "No active users found for the given company."}, status=404
            )

        tenant_users.update(is_active=False)

        return Response(
            {
                "message": f"{tenant_users.count()} user(s) under company '{company.company_name}' have been deactivated."
            },
            status=200,
        )


class DeleteTenantByCompanyView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def delete(self, request, company_id):
        try:
            company = Company.objects.get(id=company_id, created_by=request.user)
        except Exception:
            return Response(
                {"error": "Company with the given ID does not exist."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Get all tenants under this company
        tenants = Tenant.objects.filter(company=company)

        # Get all associated users
        user_ids = tenants.values_list("tenant__id", flat=True)

        # Delete users
        user_deleted_count, _ = User.objects.filter(id__in=user_ids).delete()

        # Delete tenants
        tenant_deleted_count, _ = tenants.delete()

        # Delete the company itself
        company.company_name
        company.delete()

        return Response(
            {"message": "Deleted Tenants"},
            status=status.HTTP_200_OK,
        )


class ReactivateTenantUsersAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def post(self, request, company_id):
        try:
            company = Company.objects.get(id=company_id, created_by=request.user)
        except Company.DoesNotExist:
            return Response(
                {"error": "Company not found or not owned by the user."},
                status=status.HTTP_404_NOT_FOUND,
            )

        tenants = Tenant.objects.filter(company=company)
        user_ids = tenants.values_list("tenant__id", flat=True)

        updated_count = User.objects.filter(id__in=user_ids).update(is_active=True)

        return Response(
            {
                "message": f"{updated_count} tenant users under company '{company.company_name}' have been reactivated."
            },
            status=status.HTTP_200_OK,
        )


class TenantDetailAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request, company_id):
        logger.info(
            f"Tenant detail request by user: {request.user.username} for company_id: {company_id}"
        )
        try:
            # Get company created by this admin
            company = Company.objects.get(id=company_id, created_by=request.user)
            # Get the primary tenant associated with this company
            tenant = Tenant.objects.filter(company=company).first()
            if not tenant:
                return Response(
                    {"error": "No tenant associated with this company."},
                    status=status.HTTP_404_NOT_FOUND,
                )
        except Company.DoesNotExist:
            logger.warning(
                f"Company with id {company_id} not found or not owned by {request.user.username}"
            )
            return Response(
                {
                    "error": "Company not found or you do not have permission to view it."
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = TenantDetailSerializer(tenant, context={"request": request})
        logger.success(
            f"Tenant details retrieved for company: {company.company_name} (Tenant ID: {tenant.id})"
        )
        return Response(serializer.data, status=status.HTTP_200_OK)


class TenantsByCompanyAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request, company_id):
        try:
            company = Company.objects.get(id=company_id, created_by=request.user)
        except Company.DoesNotExist:
            return Response(
                {
                    "error": "Company with the given ID does not exist or is not owned by the user."
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        logger.info(
            f"Tenants by company ID '{company_id}' requested by user: {request.user.username}"
        )

        tenants = Tenant.objects.filter(
            company=company,
            tenant__is_active=True,
            tenant__is_deleted=False,
        ).order_by("-created_at")

        paginator = PageNumberPagination()
        paginator.page_size = PaginationConstants.PAGE_SIZE
        paginated_tenants = paginator.paginate_queryset(tenants, request)

        serializer = AllTenantDetailSerializer(
            paginated_tenants, many=True, context={"request": request}
        )

        logger.success(
            f"Retrieved {tenants.count()} tenants for company: {company.company_name}"
        )

        return paginator.get_paginated_response(serializer.data)


class DistinctCompaniesAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        # Filter companies created by this user and having active, non-deleted tenants
        companies = Company.objects.filter(
            created_by=request.user,
        ).distinct()

        result = []
        for company in companies:
            tenant_count = company.tenants.filter(
                tenant__is_active=True,
                tenant__is_deleted=False,
            ).count()
            if tenant_count == 0:
                continue
            result.append(
                {
                    "id": company.id,
                    "name": company.company_name,
                    "phone_number": company.phone_number,
                    "industry": company.industry,
                    "country": company.country,
                    "tenant_count": tenant_count,
                    "profile_picture": request.build_absolute_uri(
                        company.profile_picture.url
                    )
                    if company.profile_picture
                    else None,
                    "created_at": company.created_at,
                    "updated_at": company.updated_at,
                }
            )

        return Response({"companies": result}, status=200)


class NonActiveTenantsAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        logger.info(
            f"Non-active tenant companies requested by: {request.user.username}"
        )

        companies = Company.objects.filter(created_by=request.user)
        result = []

        for company in companies:
            inactive_tenants = Tenant.objects.filter(
                company=company, tenant__is_active=False
            )

            tenant_count = inactive_tenants.count()
            if tenant_count == 0:
                continue

            result.append(
                {
                    "id": company.id,
                    "name": company.company_name,
                    "phone_number": company.phone_number,
                    "industry": company.industry,
                    "country": company.country,
                    "tenant_count": tenant_count,
                    "profile_picture": request.build_absolute_uri(
                        company.profile_picture.url
                    )
                    if company.profile_picture
                    else None,
                    "created_at": company.created_at,
                    "updated_at": company.updated_at,
                }
            )

        if not result:
            return Response(
                {"message": "No companies found with inactive tenants."},
                status=200,
            )

        logger.success(f"Found {len(result)} companies with inactive tenants.")

        return Response({"companies": result}, status=200)


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


class CustomerEPSAPIView(APIView):
    """
    APIView to return EPS data with customer name and QRadar tenant name.
    """

    permission_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        queryset = CustomerEPS.objects.select_related("qradar_tenant").all()
        serializer = CustomerEPSSerializer(queryset, many=True)
        return Response(serializer.data)


class CheckCompanyNameExistView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        company_name = request.query_params.get("company_name")
        if not company_name:
            return Response(
                {"error": "Company name is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        exists = Company.objects.filter(company_name__iexact=company_name).exists()
        if exists:
            return Response(
                {"error": "Company with this name already exists."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {"message": "Company name is available."},
            status=status.HTTP_200_OK,
        )
