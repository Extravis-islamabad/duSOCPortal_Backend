from datetime import datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal

from django.db.models import Avg, Count, Max, Q
from django.db.models.functions import TruncDate, TruncDay, TruncHour, TruncWeek
from django.utils import timezone
from loguru import logger
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from authentication.models import User
from authentication.permissions import (
    IsAdminUser,
    IsReadonlyAdminUser,
    IsSuperAdminUser,
)
from common.constants import APIConstants, FilterType, PaginationConstants
from tenant.cortex_soar_tasks import sync_soar_data
from tenant.ibm_qradar_tasks import sync_ibm_qradar_data
from tenant.itsm_tasks import sync_itsm
from tenant.models import (
    Company,
    CustomerEPS,
    DefaultSoarSlaMetric,
    DUCortexSOARIncidentFinalModel,
    IBMQradarAssests,
    IBMQradarEPS,
    SlaLevelChoices,
    SoarTenantSlaMetric,
    Tenant,
    TenantQradarMapping,
    VolumeTypeChoices,
)
from tenant.serializers import (  # TenantUpdateSerializer,
    AllTenantDetailSerializer,
    CompanyTenantUpdateSerializer,
    CustomerEPSSerializer,
    DistinctCompanySerializer,
    NonActiveCompanySerializer,
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
            company = Company.objects.get(id=company_id)
        except Company.DoesNotExist:
            return Response({"error": "Company not found."}, status=404)

        serializer = CompanyTenantUpdateSerializer(
            company, data=request.data, context={"request": request, "company": company}
        )
        if serializer.is_valid():
            # Count new users before update
            ldap_users = request.data.get("ldap_users", [])
            existing_company_users = (
                set(
                    company.tenants.filter(
                        tenant__is_active=True, tenant__is_deleted=False
                    ).values_list("tenant__username", flat=True)
                )
                if ldap_users
                else set()
            )

            new_users_count = (
                len(
                    [
                        user_data
                        for user_data in ldap_users
                        if user_data.get("username") not in existing_company_users
                    ]
                )
                if ldap_users
                else 0
            )

            serializer.save()
            logger.success(
                f"Company settings and tenant sync completed for company_id={company_id}"
            )

            response_message = "Company settings updated successfully."
            if new_users_count > 0:
                response_message += f" {new_users_count} new user(s) added."

            return Response(
                {"message": response_message, "new_users_added": new_users_count},
                status=200,
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
            company = Company.objects.get(id=company_id)
        except Exception:
            return Response(
                {"error": "Company with the given ID does not exist."},
                status=404,
            )

        # Get all tenant users under this company
        tenant_users = User.objects.filter(
            id__in=Tenant.objects.filter(company=company).values_list(
                "tenant__id", flat=True
            ),
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
                "message": f"users under company '{company.company_name}' have been deactivated."
            },
            status=200,
        )


class DeleteTenantByCompanyView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsSuperAdminUser]

    def delete(self, request, company_id):
        try:
            company = Company.objects.get(id=company_id)
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
            company = Company.objects.get(id=company_id)
        except Company.DoesNotExist:
            return Response(
                {"error": "Company not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        tenants = Tenant.objects.filter(company=company)
        user_ids = tenants.values_list("tenant__id", flat=True)

        _ = User.objects.filter(id__in=user_ids).update(is_active=True)

        return Response(
            {
                "message": f"users under company '{company.company_name}' have been reactivated."
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
            # Get company
            company = Company.objects.get(id=company_id)
            # Get the primary tenant associated with this company
            tenant = Tenant.objects.filter(company=company).first()
            if not tenant:
                return Response(
                    {"error": "No tenant associated with this company."},
                    status=status.HTTP_404_NOT_FOUND,
                )
        except Company.DoesNotExist:
            logger.warning(
                f"Company with id {company_id} not found by {request.user.username}"
            )
            return Response(
                {"error": "Company not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = TenantDetailSerializer(tenant, context={"request": request})
        logger.success(
            f"Tenant details retrieved for company: {company.company_name} (Tenant ID: {tenant.id})"
        )
        return Response(serializer.data, status=status.HTTP_200_OK)


class TenantsByCompanyAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsReadonlyAdminUser]

    def get(self, request, company_id):
        try:
            company = Company.objects.get(id=company_id)
        except Company.DoesNotExist:
            return Response(
                {"error": "Company with the given ID does not exist."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Get filter parameter for active/inactive users
        is_active_filter = request.query_params.get("is_active")

        logger.info(
            f"Tenants by company ID '{company_id}' requested by user: {request.user.username}, "
            f"is_active filter: {is_active_filter}"
        )

        # Base query - don't filter by is_active initially
        tenants = Tenant.objects.filter(
            company=company,
            tenant__is_deleted=False,
        )

        # Apply active/inactive filter based on query parameter
        if is_active_filter is not None:
            if is_active_filter.lower() == "true":
                tenants = tenants.filter(tenant__is_active=True)
                logger.info("Filtering for active tenants only")
            elif is_active_filter.lower() == "false":
                tenants = tenants.filter(tenant__is_active=False)
                logger.info("Filtering for inactive tenants only")
            else:
                return Response(
                    {
                        "error": "Invalid value for is_active parameter. Use 'true' or 'false'."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        # If no filter provided, return all non-deleted tenants (both active and inactive)

        tenants = tenants.order_by("-created_at")

        paginator = PageNumberPagination()
        paginator.page_size = PaginationConstants.PAGE_SIZE
        paginated_tenants = paginator.paginate_queryset(tenants, request)

        serializer = AllTenantDetailSerializer(
            paginated_tenants, many=True, context={"request": request}
        )

        # Get counts for logging
        active_count = tenants.filter(tenant__is_active=True).count()
        inactive_count = tenants.filter(tenant__is_active=False).count()

        logger.success(
            f"Retrieved {tenants.count()} tenants for company: {company.company_name} "
            f"(Active: {active_count}, Inactive: {inactive_count})"
        )

        return paginator.get_paginated_response(serializer.data)


class DistinctCompaniesAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsReadonlyAdminUser]

    def get(self, request):
        companies = (
            Company.objects.all()
            .annotate(
                active_tenant_count=Count(
                    "tenants",
                    filter=Q(
                        tenants__tenant__is_active=True,
                        tenants__tenant__is_deleted=False,
                    ),
                    distinct=True,
                )
            )
            .filter(active_tenant_count__gt=0)
            .order_by("id")
        )
        paginator = PageNumberPagination()
        paginator.page_size = PaginationConstants.PAGE_SIZE  # your global constant
        result_page = paginator.paginate_queryset(companies, request)

        serializer = DistinctCompanySerializer(
            result_page, many=True, context={"request": request}
        )
        return paginator.get_paginated_response(serializer.data)


class TenantManagementAPIView(APIView):
    """
    API endpoint to manage individual tenants within a company.
    Accepts company_id and tenant_id to delete or deactivate the tenant.

    Query Parameters:
    - is_deleted: If 'true', permanently deletes the tenant and user
    - is_active: If 'false', deactivates the tenant's user account

    Permissions:
    - DELETE: Only SuperAdminUsers can delete tenants
    - PATCH: AdminUsers can update/deactivate tenants
    """

    authentication_classes = [JWTAuthentication]

    def get_permissions(self):
        """
        Override to return different permission classes based on the request method.
        """
        if self.request.method == "DELETE":
            return [IsSuperAdminUser()]
        elif self.request.method == "PATCH":
            return [IsAdminUser()]
        return [IsAdminUser()]

    def delete(self, request, company_id, tenant_id):
        """
        Handle DELETE request to delete or deactivate a specific tenant.
        """
        # Get query parameters
        is_deleted = request.query_params.get("is_deleted", "").lower() == "true"
        is_active_param = request.query_params.get("is_active", "").lower()

        # Validate company exists
        try:
            company = Company.objects.get(id=company_id)
        except Company.DoesNotExist:
            return Response(
                {"error": "Company with the given ID does not exist."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Validate tenant exists and belongs to the company
        try:
            tenant = Tenant.objects.get(id=tenant_id, company=company)
        except Tenant.DoesNotExist:
            return Response(
                {
                    "error": "Tenant with the given ID does not exist or does not belong to this company."
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        # Get the associated user
        user = tenant.tenant
        if not user:
            return Response(
                {"error": "No user associated with this tenant."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Handle deletion
        if is_deleted:
            # Permanently delete the tenant and user
            username = user.username
            tenant_id_str = str(tenant.id)

            # Delete the user (this will cascade delete the tenant due to FK constraint)
            user.delete()

            logger.info(
                f"Tenant {tenant_id_str} and user '{username}' permanently deleted from company '{company.company_name}' by {request.user.username}"
            )

            return Response(
                {
                    "message": f"Tenant and user '{username}' have been permanently deleted from company '{company.company_name}'.",
                    "company_id": company_id,
                    "tenant_id": tenant_id,
                    "action": "deleted",
                },
                status=status.HTTP_200_OK,
            )

        # Handle deactivation
        elif is_active_param == "false":
            # Deactivate the user
            user.is_active = False
            user.save()

            logger.info(
                f"User '{user.username}' deactivated for tenant {tenant.id} in company '{company.company_name}' by {request.user.username}"
            )

            return Response(
                {
                    "message": f"User '{user.username}' has been deactivated.",
                    "company_id": company_id,
                    "tenant_id": tenant_id,
                    "user_id": user.id,
                    "action": "deactivated",
                },
                status=status.HTTP_200_OK,
            )

        # If neither parameter is provided correctly
        else:
            return Response(
                {
                    "error": "Please provide either 'is_deleted=true' to delete the tenant or 'is_active=false' to deactivate the user."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

    def patch(self, request, company_id, tenant_id):
        """
        Handle PATCH request to update tenant status (activate/deactivate).
        """
        # Validate company exists
        try:
            company = Company.objects.get(id=company_id)
        except Company.DoesNotExist:
            return Response(
                {"error": "Company with the given ID does not exist."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Validate tenant exists and belongs to the company
        try:
            tenant = Tenant.objects.get(id=tenant_id, company=company)
        except Tenant.DoesNotExist:
            return Response(
                {
                    "error": "Tenant with the given ID does not exist or does not belong to this company."
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        # Get the associated user
        user = tenant.tenant
        if not user:
            return Response(
                {"error": "No user associated with this tenant."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Get the is_active status from request body
        is_active = request.data.get("is_active")

        if is_active is None:
            return Response(
                {"error": "Please provide 'is_active' field in the request body."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Update user's active status
        user.is_active = bool(is_active)
        user.save()

        action = "activated" if user.is_active else "deactivated"

        logger.info(
            f"User '{user.username}' {action} for tenant {tenant.id} in company '{company.company_name}' by {request.user.username}"
        )

        return Response(
            {
                "message": f"User '{user.username}' has been {action}.",
                "company_id": company_id,
                "tenant_id": tenant_id,
                "user_id": user.id,
                "is_active": user.is_active,
                "action": action,
            },
            status=status.HTTP_200_OK,
        )


class NonActiveTenantsAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsReadonlyAdminUser]

    def get(self, request):
        logger.info(
            f"Non-active tenant companies requested by: {request.user.username}"
        )

        # Step 1: Annotate companies with counts of total, inactive, and active tenants
        companies = (
            Company.objects.all()
            .annotate(
                total_tenant_count=Count(
                    "tenants",
                    filter=Q(tenants__tenant__isnull=False),
                    distinct=True,
                ),
                inactive_tenant_count=Count(
                    "tenants",
                    filter=Q(tenants__tenant__is_active=False),
                    distinct=True,
                ),
                active_tenant_count=Count(
                    "tenants",
                    filter=Q(tenants__tenant__is_active=True),
                    distinct=True,
                ),
            )
            # Only include companies where:
            # 1. They have at least one tenant (total_tenant_count > 0)
            # 2. ALL tenants are inactive (active_tenant_count = 0 and inactive_tenant_count > 0)
            .filter(
                total_tenant_count__gt=0,
                active_tenant_count=0,
                inactive_tenant_count__gt=0,
            )
            .order_by("id")
        )

        if not companies.exists():
            return Response(
                {"message": "No companies found where all users are inactive."},
                status=200,
            )

        # Step 2: Paginate the result
        paginator = PageNumberPagination()
        paginator.page_size = PaginationConstants.PAGE_SIZE  # or hardcode if needed
        paginated_companies = paginator.paginate_queryset(companies, request)

        # Step 3: Serialize the result
        serializer = NonActiveCompanySerializer(
            paginated_companies, many=True, context={"request": request}
        )

        logger.success(
            f"Found {companies.count()} companies where all users are inactive."
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


class AssetsSummaryAPIView(APIView):
    """
    APIView to return assets summary for all tenants or a specific company.
    Returns total, active (reporting), and non-reporting assets.
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsReadonlyAdminUser]

    def get(self, request):
        company_id = request.query_params.get("company_id")
        logger.info(
            f"Assets summary requested by user: {request.user.username}, company_id: {company_id}"
        )

        try:
            if company_id:
                # Get assets for specific company
                try:
                    company = Company.objects.get(id=company_id)
                    companies = [company]
                except Company.DoesNotExist:
                    return Response(
                        {"error": "Company not found or unauthorized."},
                        status=status.HTTP_404_NOT_FOUND,
                    )
            else:
                # Get assets for all companies
                companies = Company.objects.all()
                if not companies.exists():
                    return Response(
                        {
                            "message": "No companies found.",
                            "summary": self._get_empty_summary(),
                        },
                        status=status.HTTP_200_OK,
                    )

            # Calculate assets summary
            summary = self._calculate_assets_summary(companies)

            logger.success(
                f"Assets summary calculated successfully for {len(companies)} companies"
            )

            return Response(summary, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error calculating assets summary: {str(e)}")
            return Response(
                {"error": "Internal server error while calculating assets summary."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _get_empty_summary(self):
        """Return empty summary structure"""
        return {
            "companies_count": 0,
            "companies_summary": [],
        }

    def _calculate_assets_summary(self, companies):
        """Calculate assets summary per company"""
        companies_summary = []
        for company in companies:
            # Get all event collector IDs for this company
            collector_ids = TenantQradarMapping.objects.filter(
                company=company
            ).values_list("event_collectors__id", flat=True)

            if not collector_ids:
                # Company has no QRadar mappings
                companies_summary.append(
                    {
                        "company_id": company.id,
                        "company_name": company.company_name,
                        "integrated_assets": 0,
                        "active_assets": 0,
                        "no_reporting_assets": 0,
                    }
                )
                continue

            # Get assets for this company's collectors
            assets_qs = IBMQradarAssests.objects.filter(
                event_collector_id__in=collector_ids
            ).select_related("log_source_type")

            assets = list(assets_qs)
            company_integrated_assets = len(assets)
            company_active_assets = 0
            company_no_reporting_assets = 0

            company_active_assets = (
                IBMQradarAssests.objects.filter(event_collector_id__in=collector_ids)
                .select_related("log_source_type")
                .filter(is_active=True)
                .count()
            )

            company_no_reporting_assets = (
                IBMQradarAssests.objects.filter(event_collector_id__in=collector_ids)
                .select_related("log_source_type")
                .filter(is_active=False)
                .count()
            )

            # Add to company summary
            companies_summary.append(
                {
                    "company_id": company.id,
                    "company_name": company.company_name,
                    "integrated_assets": company_integrated_assets,
                    "active_assets": company_active_assets,
                    "no_reporting_assets": company_no_reporting_assets,
                }
            )

        return {
            "companies_count": len(companies),
            "companies_summary": companies_summary,
        }


class IncidentPrioritySummaryAPIView(APIView):
    """
    APIView to return incident priority summary for all tenants or a specific company.
    Returns count of true positive and false positive incidents grouped by priority.
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsReadonlyAdminUser]

    def get(self, request):
        company_id = request.query_params.get("company_id")
        priority = request.query_params.get("priority")  # 1, 2, 3, 4

        logger.info(
            f"Incident priority summary requested by user: {request.user.username}, "
            f"company_id: {company_id}, priority: {priority}"
        )

        try:
            if company_id:
                # Get incidents for specific company
                try:
                    company = Company.objects.get(id=company_id)
                    companies = [company]
                except Company.DoesNotExist:
                    return Response(
                        {"error": "Company not found or unauthorized."},
                        status=status.HTTP_404_NOT_FOUND,
                    )
            else:
                # Get incidents for all companies
                companies = Company.objects.all()
                if not companies.exists():
                    return Response(
                        {
                            "message": "No companies found.",
                            "summary": self._get_empty_incident_summary(),
                        },
                        status=status.HTTP_200_OK,
                    )

            # Calculate incident priority summary
            summary = self._calculate_incident_priority_summary(companies, priority)

            logger.success(
                f"Incident priority summary calculated successfully for {len(companies)} companies"
            )

            return Response(summary, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error calculating incident priority summary: {str(e)}")
            return Response(
                {
                    "error": "Internal server error while calculating incident priority summary."
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _get_empty_incident_summary(self):
        """Return empty incident summary structure"""
        return {
            "companies_count": 0,
            "companies_summary": [],
        }

    def _calculate_incident_priority_summary(self, companies, priority_filter):
        """Calculate incident priority summary per company"""
        companies_summary = []

        for company in companies:
            # Get all SOAR tenant IDs for this company
            soar_ids = company.soar_tenants.values_list("id", flat=True)

            if not soar_ids:
                # Company has no SOAR tenants
                companies_summary.append(
                    {
                        "company_id": company.id,
                        "company_name": company.company_name,
                        "priority_summary": self._get_empty_priority_breakdown(),
                    }
                )
                continue

            # Build base filter for company's SOAR tenants
            base_filters = Q(cortex_soar_tenant__in=soar_ids)

            # Apply priority filter if specified
            if priority_filter:
                priority_mapping = {
                    "1": "P4",  # P4 Low
                    "2": "P3",  # P3 Medium
                    "3": "P2",  # P2 High
                    "4": "P1",  # P1 Critical
                }
                if priority_filter in priority_mapping:
                    priority_string = priority_mapping[priority_filter]
                    base_filters &= Q(incident_priority__icontains=priority_string)

            # Get priority breakdown for this company
            priority_summary = self._get_priority_breakdown(base_filters)

            companies_summary.append(
                {
                    "company_id": company.id,
                    "company_name": company.company_name,
                    "priority_summary": priority_summary,
                }
            )

        return {
            "companies_count": len(companies),
            "companies_summary": companies_summary,
        }

    def _get_priority_breakdown(self, base_filters):
        """Get total incident counts by priority (only true positive OR false positive)"""
        priority_breakdown = []

        # Define priority mappings
        priorities = [
            {"priority": "P1 Critical", "filter_key": "P1"},
            {"priority": "P2 High", "filter_key": "P2"},
            {"priority": "P3 Medium", "filter_key": "P3"},
            {"priority": "P4 Low", "filter_key": "P4"},
        ]

        for priority_info in priorities:
            priority_name = priority_info["priority"]
            priority_key = priority_info["filter_key"]

            # Filter for this specific priority
            priority_filters = base_filters & Q(
                incident_priority__icontains=priority_key
            )

            # True Positive Logic: Ready incidents with proper fields
            true_positive_filters = priority_filters & (
                ~Q(owner__isnull=True)
                & ~Q(owner__exact="")
                & Q(incident_tta__isnull=False)
                & Q(incident_ttn__isnull=False)
                & Q(incident_ttdn__isnull=False)
                & Q(itsm_sync_status__isnull=False)
                & Q(itsm_sync_status__iexact="Ready")
            )

            # False Positive Logic: Done incidents
            false_positive_filters = priority_filters & Q(
                itsm_sync_status__iexact="Done"
            )

            # Combine true positive OR false positive (using union to avoid duplicates)
            combined_filters = true_positive_filters | false_positive_filters

            total_count = DUCortexSOARIncidentFinalModel.objects.filter(
                combined_filters
            ).count()

            priority_breakdown.append(
                {"priority": priority_name, "total_count": total_count}
            )

        return priority_breakdown

    def _get_empty_priority_breakdown(self):
        """Return empty priority breakdown structure"""
        return [
            {"priority": "P1 Critical", "total_count": 0},
            {"priority": "P2 High", "total_count": 0},
            {"priority": "P3 Medium", "total_count": 0},
            {"priority": "P4 Low", "total_count": 0},
        ]


class IncidentStatusSummaryAPIView(APIView):
    """
    APIView to return incident status summary for all tenants or a specific company.
    Returns count of open and closed incidents.
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsReadonlyAdminUser]

    def get(self, request):
        company_id = request.query_params.get("company_id")

        logger.info(
            f"Incident status summary requested by user: {request.user.username}, "
            f"company_id: {company_id}"
        )

        try:
            if company_id:
                # Get incidents for specific company
                try:
                    company = Company.objects.get(id=company_id)
                    companies = [company]
                except Company.DoesNotExist:
                    return Response(
                        {"error": "Company not found or unauthorized."},
                        status=status.HTTP_404_NOT_FOUND,
                    )
            else:
                # Get incidents for all companies
                companies = Company.objects.all()
                if not companies.exists():
                    return Response(
                        {
                            "message": "No companies found.",
                            "summary": self._get_empty_status_summary(),
                        },
                        status=status.HTTP_200_OK,
                    )

            # Calculate incident status summary
            summary = self._calculate_incident_status_summary(companies, request)

            logger.success(
                f"Incident status summary calculated successfully for {len(companies)} companies"
            )

            return Response(summary, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error calculating incident status summary: {str(e)}")
            return Response(
                {
                    "error": "Internal server error while calculating incident status summary."
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _get_empty_status_summary(self):
        """Return empty status summary structure"""
        return {
            "companies_count": 0,
            "companies_summary": [],
        }

    def _apply_date_filters(self, request, base_filters):
        """Apply date filtering logic similar to other incident views"""
        filters = base_filters
        now = timezone.now().date()
        filter_type = request.query_params.get("filter_type")
        start_date_str = request.query_params.get("start_date")
        end_date_str = request.query_params.get("end_date")

        if start_date_str and end_date_str:
            try:
                start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
                end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
                filters &= Q(created__date__gte=start_date) & Q(
                    created__date__lte=end_date
                )
            except ValueError:
                # Invalid date format, but don't fail the request, just ignore the filter
                pass
        elif filter_type:
            try:
                filter_type = FilterType(int(filter_type))
                if filter_type == FilterType.TODAY:
                    filters &= Q(created__date=now)
                elif filter_type == FilterType.WEEK:
                    start_date = now - timedelta(days=7)
                    filters &= Q(created__date__gte=start_date)
                elif filter_type == FilterType.MONTH:
                    start_date = now - timedelta(days=30)
                    filters &= Q(created__date__gte=start_date)
                # elif filter_type == FilterType.QUARTER:
                #     start_date = now - timedelta(days=90)
                #     filters &= Q(created__date__gte=start_date)
                # elif filter_type == FilterType.YEAR:
                #     start_date = now - timedelta(days=365)
                #     filters &= Q(created__date__gte=start_date)
            except Exception as e:
                logger.error(f"Error applying date filter: {str(e)}")

        return filters

    def _calculate_incident_status_summary(self, companies, request):
        """Calculate incident status summary per company with date filtering"""
        companies_summary = []

        for company in companies:
            # Get all SOAR tenant IDs for this company
            soar_ids = company.soar_tenants.values_list("id", flat=True)

            if not soar_ids:
                # Company has no SOAR tenants
                companies_summary.append(
                    {
                        "company_id": company.id,
                        "company_name": company.company_name,
                        "open_incidents": 0,
                        "closed_incidents": 0,
                        "total_incidents": 0,
                    }
                )
                continue

            # Build base filter for company's SOAR tenants with true/false positive logic
            base_filters = self._get_valid_incidents_filter(soar_ids)

            # Apply date filters
            filters = self._apply_date_filters(request, base_filters)

            # Count open incidents (status = "1" or phases not in closed states)
            open_filters = filters & (Q(status="1"))
            open_count = DUCortexSOARIncidentFinalModel.objects.filter(
                open_filters
            ).count()

            # Count closed incidents (status = "2" or phases in closed states)
            closed_filters = filters & (Q(status="2"))
            closed_count = DUCortexSOARIncidentFinalModel.objects.filter(
                closed_filters
            ).count()

            total_count = open_count + closed_count

            companies_summary.append(
                {
                    "company_id": company.id,
                    "company_name": company.company_name,
                    "open_incidents": open_count,
                    "closed_incidents": closed_count,
                    "total_incidents": total_count,
                }
            )

        return {
            "companies_count": len(companies),
            "companies_summary": companies_summary,
        }

    def _get_valid_incidents_filter(self, soar_ids):
        """Get filter for incidents that match true positive OR false positive logic"""
        base_filters = Q(cortex_soar_tenant__in=soar_ids)

        # True Positive Logic: Ready incidents with proper fields
        true_positive_filters = base_filters & (
            ~Q(owner__isnull=True)
            & ~Q(owner__exact="")
            & Q(incident_tta__isnull=False)
            & Q(incident_ttn__isnull=False)
            & Q(incident_ttdn__isnull=False)
            & Q(itsm_sync_status__isnull=False)
            & Q(itsm_sync_status__iexact="Ready")
        )

        # False Positive Logic: Done incidents
        false_positive_filters = base_filters & Q(itsm_sync_status__iexact="Done")

        # Combine true positive OR false positive
        return true_positive_filters | false_positive_filters


class TenantSLAMatrixAPIView(APIView):
    """
    APIView to return SLA metrics matrix for a specific company or all companies.
    Returns SLA compliance data for incidents across different priority levels.
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsReadonlyAdminUser]

    def get(self, request):
        company_id = request.query_params.get("company_id")

        logger.info(
            f"Tenant SLA Matrix requested by user: {request.user.username}, "
            f"company_id: {company_id}"
        )

        try:
            if company_id:
                # Get SLA matrix for specific company
                try:
                    company = Company.objects.get(id=company_id)
                    companies = [company]
                except Company.DoesNotExist:
                    return Response(
                        {"error": "Company not found or unauthorized."},
                        status=status.HTTP_404_NOT_FOUND,
                    )
            else:
                # Get SLA matrix for all companies
                companies = Company.objects.all()
                if not companies.exists():
                    return Response(
                        {
                            "message": "No companies found.",
                            "companies": [],
                        },
                        status=status.HTTP_200_OK,
                    )

            # Calculate SLA matrix for each company
            companies_sla_data = []
            for company in companies:
                company_sla_data = self._calculate_company_sla_matrix(company, request)
                companies_sla_data.append(company_sla_data)

            response_data = {
                "companies_count": len(companies),
                "companies": companies_sla_data,
            }

            logger.success(
                f"Tenant SLA Matrix calculated successfully for {len(companies)} companies"
            )

            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error calculating Tenant SLA Matrix: {str(e)}")
            return Response(
                {"error": "Internal server error while calculating Tenant SLA Matrix."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _calculate_company_sla_matrix(self, company, request):
        """Calculate SLA matrix for a specific company with date filtering"""
        # Get all SOAR tenant IDs for this company
        soar_ids = company.soar_tenants.values_list("id", flat=True)

        if not soar_ids:
            # Company has no SOAR tenants, return empty data
            return {
                "company_id": company.id,
                "company_name": company.company_name,
                "is_default_sla": company.is_default_sla,
                "total_incidents_count": 0,
                "sla_metrics": self._get_empty_sla_metrics(),
            }

        # Determine if company uses default SLA metrics or custom ones
        is_default = company.is_default_sla
        if is_default:
            sla_metrics = DefaultSoarSlaMetric.objects.all()
        else:
            sla_metrics = SoarTenantSlaMetric.objects.filter(
                soar_tenant__in=soar_ids, company=company
            )

        # Create a dictionary of SLA metrics by level for quick lookup
        sla_metrics_dict = {metric.sla_level: metric for metric in sla_metrics}

        # Get valid incidents (true positive OR false positive)
        base_filters = self._get_valid_incidents_filter(soar_ids)
        base_filters &= Q(
            incident_priority__in=[
                SlaLevelChoices.P1.label,
                SlaLevelChoices.P2.label,
                SlaLevelChoices.P3.label,
                SlaLevelChoices.P4.label,
            ]
        )

        # We need TTA, TTN, and TTDN fields to calculate SLA compliance
        base_filters &= (
            Q(incident_tta__isnull=False)
            & Q(incident_ttn__isnull=False)
            & Q(incident_ttdn__isnull=False)
        )

        # Apply date filters
        filters = self._apply_date_filters(request, base_filters)

        incidents = DUCortexSOARIncidentFinalModel.objects.filter(
            filters
        ).select_related()

        # Initialize SLA metrics structure for all priority levels
        sla_metrics_data = {}
        for priority_level in [
            SlaLevelChoices.P1,
            SlaLevelChoices.P2,
            SlaLevelChoices.P3,
            SlaLevelChoices.P4,
        ]:
            sla_metrics_data[priority_level.label] = {
                "priority": priority_level.label,
                "priority_name": priority_level.name,
                "total_incidents": 0,
                "tta": {
                    "sla_minutes": sla_metrics_dict.get(priority_level, {}).tta_minutes
                    if sla_metrics_dict.get(priority_level)
                    else None,
                    "compliant_count": 0,
                    "breached_count": 0,
                    "compliance_percentage": 0,
                },
                "ttn": {
                    "sla_minutes": sla_metrics_dict.get(priority_level, {}).ttn_minutes
                    if sla_metrics_dict.get(priority_level)
                    else None,
                    "compliant_count": 0,
                    "breached_count": 0,
                    "compliance_percentage": 0,
                },
                "ttdn": {
                    "sla_minutes": sla_metrics_dict.get(priority_level, {}).ttdn_minutes
                    if sla_metrics_dict.get(priority_level)
                    else None,
                    "compliant_count": 0,
                    "breached_count": 0,
                    "compliance_percentage": 0,
                },
                "overall_compliance": {
                    "fully_compliant_count": 0,
                    "partially_compliant_count": 0,
                    "non_compliant_count": 0,
                    "compliance_percentage": 0,
                },
            }

        # Process incidents and calculate metrics
        for incident in incidents:
            priority = incident.incident_priority
            # Skip if priority doesn't match any of our defined levels
            if priority not in sla_metrics_data:
                continue

            # Find the corresponding SLA level
            sla_level = None
            for level in [
                SlaLevelChoices.P1,
                SlaLevelChoices.P2,
                SlaLevelChoices.P3,
                SlaLevelChoices.P4,
            ]:
                if priority == level.label:
                    sla_level = level
                    break

            if not sla_level or sla_level not in sla_metrics_dict:
                continue

            sla = sla_metrics_dict[sla_level]
            metric_data = sla_metrics_data[priority]
            metric_data["total_incidents"] += 1

            # Count the number of SLA breaches for this incident
            breach_count = 0

            # Calculate TTA compliance
            tta_delta = (incident.incident_tta - incident.occured).total_seconds() / 60
            if tta_delta <= sla.tta_minutes:
                metric_data["tta"]["compliant_count"] += 1
            else:
                metric_data["tta"]["breached_count"] += 1
                breach_count += 1

            # Calculate TTN compliance
            ttn_delta = (incident.incident_ttn - incident.occured).total_seconds() / 60
            if ttn_delta <= sla.ttn_minutes:
                metric_data["ttn"]["compliant_count"] += 1
            else:
                metric_data["ttn"]["breached_count"] += 1
                breach_count += 1

            # Calculate TTDN compliance
            ttdn_delta = (
                incident.incident_ttdn - incident.occured
            ).total_seconds() / 60
            if ttdn_delta <= sla.ttdn_minutes:
                metric_data["ttdn"]["compliant_count"] += 1
            else:
                metric_data["ttdn"]["breached_count"] += 1
                breach_count += 1

            # Update overall compliance statistics
            if breach_count == 0:
                metric_data["overall_compliance"]["fully_compliant_count"] += 1
            elif (
                breach_count < 3
            ):  # Partially compliant if at least one metric is compliant
                metric_data["overall_compliance"]["partially_compliant_count"] += 1
            else:  # All metrics breached
                metric_data["overall_compliance"]["non_compliant_count"] += 1

        # Calculate percentages for all metrics
        for priority, data in sla_metrics_data.items():
            total = data["total_incidents"]
            if total > 0:
                # Calculate compliance percentages for each metric
                data["tta"]["compliance_percentage"] = round(
                    (data["tta"]["compliant_count"] / total) * 100, 2
                )
                data["ttn"]["compliance_percentage"] = round(
                    (data["ttn"]["compliant_count"] / total) * 100, 2
                )
                data["ttdn"]["compliance_percentage"] = round(
                    (data["ttdn"]["compliant_count"] / total) * 100, 2
                )

                # Calculate overall compliance percentage based on fully compliant incidents
                data["overall_compliance"]["compliance_percentage"] = round(
                    (data["overall_compliance"]["fully_compliant_count"] / total) * 100,
                    2,
                )

        # Calculate total incidents count across all priorities (unique incidents count)
        total_incidents_count = sum(
            data["total_incidents"] for data in sla_metrics_data.values()
        )

        return {
            "company_id": company.id,
            "company_name": company.company_name,
            "is_default_sla": is_default,
            "total_incidents_count": total_incidents_count,
            "sla_metrics": list(sla_metrics_data.values()),
        }

    def _apply_date_filters(self, request, base_filters):
        """Apply date filtering logic similar to other incident views"""
        filters = base_filters
        now = timezone.now().date()
        filter_type = request.query_params.get("filter_type")
        start_date_str = request.query_params.get("start_date")
        end_date_str = request.query_params.get("end_date")

        if start_date_str and end_date_str:
            try:
                start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
                end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
                filters &= Q(created__date__gte=start_date) & Q(
                    created__date__lte=end_date
                )
            except ValueError:
                # Invalid date format, but don't fail the request, just ignore the filter
                pass
        elif filter_type:
            try:
                filter_type = FilterType(int(filter_type))
                if filter_type == FilterType.TODAY:
                    filters &= Q(created__date=now)
                elif filter_type == FilterType.WEEK:
                    start_date = now - timedelta(days=7)
                    filters &= Q(created__date__gte=start_date)
                elif filter_type == FilterType.MONTH:
                    start_date = now - timedelta(days=30)
                    filters &= Q(created__date__gte=start_date)
                # elif filter_type == FilterType.QUARTER:
                #     start_date = now - timedelta(days=90)
                #     filters &= Q(created__date__gte=start_date)
                # elif filter_type == FilterType.YEAR:
                #     start_date = now - timedelta(days=365)
                #     filters &= Q(created__date__gte=start_date)
            except Exception as e:
                logger.error(f"Error applying date filter: {str(e)}")

        return filters

    def _get_valid_incidents_filter(self, soar_ids):
        """Get filter for incidents that match true positive OR false positive logic"""
        base_filters = Q(cortex_soar_tenant__in=soar_ids)

        # True Positive Logic: Ready incidents with proper fields
        true_positive_filters = base_filters & (
            ~Q(owner__isnull=True)
            & ~Q(owner__exact="")
            & Q(incident_tta__isnull=False)
            & Q(incident_ttn__isnull=False)
            & Q(incident_ttdn__isnull=False)
            & Q(itsm_sync_status__isnull=False)
            & Q(itsm_sync_status__iexact="Ready")
        )

        # False Positive Logic: Done incidents
        false_positive_filters = base_filters & Q(itsm_sync_status__iexact="Done")

        # Combine true positive OR false positive
        return true_positive_filters | false_positive_filters

    def _get_empty_sla_metrics(self):
        """Return empty SLA metrics structure for all priority levels"""
        empty_metrics = []
        for priority_level in [
            SlaLevelChoices.P1,
            SlaLevelChoices.P2,
            SlaLevelChoices.P3,
            SlaLevelChoices.P4,
        ]:
            empty_metrics.append(
                {
                    "priority": priority_level.label,
                    "priority_name": priority_level.name,
                    "total_incidents": 0,
                    "tta": {
                        "sla_minutes": None,
                        "compliant_count": 0,
                        "breached_count": 0,
                        "compliance_percentage": 0,
                    },
                    "ttn": {
                        "sla_minutes": None,
                        "compliant_count": 0,
                        "breached_count": 0,
                        "compliance_percentage": 0,
                    },
                    "ttdn": {
                        "sla_minutes": None,
                        "compliant_count": 0,
                        "breached_count": 0,
                        "compliance_percentage": 0,
                    },
                    "overall_compliance": {
                        "fully_compliant_count": 0,
                        "partially_compliant_count": 0,
                        "non_compliant_count": 0,
                        "compliance_percentage": 0,
                    },
                }
            )
        return empty_metrics


class IncidentCompletionStatusAPIView(APIView):
    """
    APIView to return incident completion status by priority for a specific company.
    Shows total incidents and completed incidents (SLA compliant) for each priority level.
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsReadonlyAdminUser]

    def get(self, request):
        company_id = request.query_params.get("company_id")

        if not company_id:
            return Response(
                {"error": "company_id query parameter is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        logger.info(
            f"Incident completion status requested by user: {request.user.username}, "
            f"company_id: {company_id}"
        )

        try:
            # Get company
            try:
                company = Company.objects.get(id=company_id)
            except Company.DoesNotExist:
                return Response(
                    {"error": "Company not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Get all SOAR tenant IDs for this company
            soar_ids = company.soar_tenants.values_list("id", flat=True)
            if not soar_ids:
                return Response(
                    {
                        "message": "No SOAR tenants found for this company.",
                        "completion_status": self._get_empty_completion_status(),
                    },
                    status=status.HTTP_200_OK,
                )

            # Build base filter for true positive and false positive incidents
            true_positive_filters = Q(cortex_soar_tenant__in=soar_ids) & (
                ~Q(owner__isnull=True)
                & ~Q(owner__exact="")
                & Q(incident_tta__isnull=False)
                & Q(incident_ttn__isnull=False)
                & Q(incident_ttdn__isnull=False)
                & Q(itsm_sync_status__isnull=False)
                & Q(itsm_sync_status__iexact="Ready")
                & Q(incident_priority__isnull=False)
                & ~Q(incident_priority__exact="")
            )

            false_positive_filters = Q(cortex_soar_tenant__in=soar_ids) & Q(
                itsm_sync_status__iexact="Done"
            )

            base_filters = true_positive_filters | false_positive_filters

            # Apply additional date filters if provided
            filters = self._apply_date_filters(request, base_filters)

            # Get incidents
            incidents = DUCortexSOARIncidentFinalModel.objects.filter(filters)

            # Get SLA metrics for the company
            completion_status = self._calculate_completion_status(company, incidents)

            logger.success(
                f"Incident completion status calculated successfully for company {company.company_name}"
            )

            return Response(completion_status, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error calculating incident completion status: {str(e)}")
            return Response(
                {
                    "error": "Internal server error while calculating incident completion status."
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _apply_date_filters(self, request, base_filters):
        """Apply date filtering logic similar to SLA severity incidents view"""
        filters = base_filters
        now = timezone.now().date()
        filter_type = request.query_params.get("filter_type")
        start_date_str = request.query_params.get("start_date")
        end_date_str = request.query_params.get("end_date")

        if start_date_str and end_date_str:
            try:
                start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
                end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
                filters &= Q(created__date__gte=start_date) & Q(
                    created__date__lte=end_date
                )
            except ValueError:
                # Invalid date format, but don't fail the request, just ignore the filter
                pass
        elif filter_type:
            try:
                filter_type = FilterType(int(filter_type))
                if filter_type == FilterType.TODAY:
                    filters &= Q(created__date=now)
                elif filter_type == FilterType.WEEK:
                    start_date = now - timedelta(days=7)
                    filters &= Q(created__date__gte=start_date)
                elif filter_type == FilterType.MONTH:
                    start_date = now - timedelta(days=30)
                    filters &= Q(created__date__gte=start_date)
                # elif filter_type == FilterType.QUARTER:
                #     start_date = now - timedelta(days=90)
                #     filters &= Q(created__date__gte=start_date)
                # elif filter_type == FilterType.YEAR:
                #     start_date = now - timedelta(days=365)
                #     filters &= Q(created__date__gte=start_date)
            except Exception as e:
                logger.error(f"Error applying date filters: {str(e)}")
                # Don't fail the request, just ignore the filter

        return filters

    def _calculate_completion_status(self, company, incidents):
        """Calculate completion status for each priority level"""
        # Get SLA metrics
        if company.is_default_sla:
            sla_metrics = DefaultSoarSlaMetric.objects.all()
        else:
            sla_metrics = SoarTenantSlaMetric.objects.filter(company=company)

        sla_metrics_dict = {metric.sla_level: metric for metric in sla_metrics}

        # Priority mappings
        priority_to_sla_map = {
            "P1 Critical": SlaLevelChoices.P1,
            "P2 High": SlaLevelChoices.P2,
            "P3 Medium": SlaLevelChoices.P3,
            "P4 Low": SlaLevelChoices.P4,
        }
        sla_to_label_map = {
            SlaLevelChoices.P1: "p1_critical",
            SlaLevelChoices.P2: "p2_high",
            SlaLevelChoices.P3: "p3_medium",
            SlaLevelChoices.P4: "p4_low",
        }

        # Initialize counts
        completion_counts = {
            "p1_critical": {
                "total_incidents": 0,
                "completed_incidents": 0,
                "completion_percentage": 0,
            },
            "p2_high": {
                "total_incidents": 0,
                "completed_incidents": 0,
                "completion_percentage": 0,
            },
            "p3_medium": {
                "total_incidents": 0,
                "completed_incidents": 0,
                "completion_percentage": 0,
            },
            "p4_low": {
                "total_incidents": 0,
                "completed_incidents": 0,
                "completion_percentage": 0,
            },
        }

        # Process each incident
        for incident in incidents:
            sla_level = priority_to_sla_map.get(incident.incident_priority)
            if not sla_level:
                continue

            sla_metric = sla_metrics_dict.get(sla_level)
            if not sla_metric:
                continue

            label = sla_to_label_map[sla_level]
            created = incident.created
            is_completed = True  # Assume completed until we find a breach

            # Check if all SLA metrics are met (similar to SLA severity incidents)
            if incident.incident_tta:
                if (
                    incident.incident_tta - created
                ).total_seconds() / 60 > sla_metric.tta_minutes:
                    is_completed = False
            if incident.incident_ttn:
                if (
                    incident.incident_ttn - created
                ).total_seconds() / 60 > sla_metric.ttn_minutes:
                    is_completed = False
            if incident.incident_ttdn:
                if (
                    incident.incident_ttdn - created
                ).total_seconds() / 60 > sla_metric.ttdn_minutes:
                    is_completed = False

            completion_counts[label]["total_incidents"] += 1
            if is_completed:
                completion_counts[label]["completed_incidents"] += 1

        # Calculate completion percentages
        for priority_data in completion_counts.values():
            total = priority_data["total_incidents"]
            if total > 0:
                priority_data["completion_percentage"] = round(
                    (priority_data["completed_incidents"] / total) * 100, 2
                )

        # Calculate overall statistics
        total_incidents = sum(
            data["total_incidents"] for data in completion_counts.values()
        )
        total_completed = sum(
            data["completed_incidents"] for data in completion_counts.values()
        )
        overall_completion_percentage = (
            round((total_completed / total_incidents) * 100, 2)
            if total_incidents > 0
            else 0
        )

        return {
            "company_id": company.id,
            "company_name": company.company_name,
            "is_default_sla": company.is_default_sla,
            "total_incidents": total_incidents,
            "total_completed_incidents": total_completed,
            "overall_completion_percentage": overall_completion_percentage,
            "priority_breakdown": completion_counts,
            "completion_status": "good"
            if overall_completion_percentage >= 80
            else "needs_attention",
        }

    def _get_empty_completion_status(self):
        """Return empty completion status structure"""
        return {
            "p1_critical": {
                "total_incidents": 0,
                "completed_incidents": 0,
                "completion_percentage": 0,
            },
            "p2_high": {
                "total_incidents": 0,
                "completed_incidents": 0,
                "completion_percentage": 0,
            },
            "p3_medium": {
                "total_incidents": 0,
                "completed_incidents": 0,
                "completion_percentage": 0,
            },
            "p4_low": {
                "total_incidents": 0,
                "completed_incidents": 0,
                "completion_percentage": 0,
            },
        }


class EPSUtilizationAPIView(APIView):
    """
    APIView to return EPS utilization graph data for a specific company or all companies.
    Returns time-series EPS data with contractual volume information.
    If company_id is provided, returns data for that specific company.
    If company_id is not provided, returns data for all companies owned by the admin.
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        company_id = request.query_params.get("company_id")

        logger.info(
            f"EPS utilization requested by user: {request.user.username}, "
            f"company_id: {company_id if company_id else 'all companies'}"
        )

        try:
            # Get filter type parameter
            try:
                filter_value = int(
                    request.query_params.get("filter_type", FilterType.TODAY.value)
                )
                filter_enum = FilterType(filter_value)
            except (ValueError, KeyError):
                return Response(
                    {"error": "Invalid filter value."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Calculate time range and truncation based on filter type
            now = timezone.now()
            time_trunc, start_time, end_time = self._get_time_range_and_truncation(
                filter_enum, now, request
            )

            if start_time is None:  # Error case
                return time_trunc  # Return the error response

            if company_id:
                # Return data for specific company
                return self._get_company_eps_data(
                    request, company_id, filter_enum, time_trunc, start_time, end_time
                )
            else:
                # Return data for all companies
                return self._get_all_companies_eps_data(
                    request, filter_enum, time_trunc, start_time, end_time
                )

        except Exception as e:
            logger.error(f"Error calculating EPS utilization: {str(e)}")
            return Response(
                {"error": "Internal server error while calculating EPS utilization."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _get_company_eps_data(
        self, request, company_id, filter_enum, time_trunc, start_time, end_time
    ):
        """Get EPS data for a specific company"""
        try:
            company = Company.objects.get(id=company_id, created_by=request.user)
        except Company.DoesNotExist:
            return Response(
                {"error": "Company not found or unauthorized."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Get QRadar tenant IDs for this company
        qradar_tenant_ids = company.qradar_mappings.values_list(
            "qradar_tenant__id", flat=True
        )

        if not qradar_tenant_ids:
            return Response(
                {
                    "message": "No QRadar tenants found for this company.",
                    "company_id": company.id,
                    "company_name": company.company_name,
                    "contracted_volume": None,
                    "contracted_volume_type": None,
                    "contracted_volume_type_display": None,
                    "eps_graph": [],
                    "utilization_stats": self._get_empty_utilization_stats(),
                },
                status=status.HTTP_200_OK,
            )

        # Build filter kwargs for EPS data
        filter_kwargs = {"domain_id__in": qradar_tenant_ids}
        if filter_enum == FilterType.CUSTOM_RANGE:
            filter_kwargs["created_at__range"] = (start_time, end_time)
        else:
            filter_kwargs["created_at__gte"] = start_time

        # Query EPS data with aggregation
        eps_data_raw = (
            IBMQradarEPS.objects.filter(**filter_kwargs)
            .annotate(interval=time_trunc)
            .values("interval")
            .annotate(average_eps=Avg("average_eps"), peak_eps=Max("peak_eps"))
            .order_by("interval")
        )

        # Format EPS data for response
        eps_data = self._format_eps_data(
            eps_data_raw, filter_enum, filter_kwargs, time_trunc
        )

        # Get contracted volume information
        mapping = TenantQradarMapping.objects.filter(company=company).first()
        contracted_volume = mapping.contracted_volume if mapping else None
        contracted_volume_type = mapping.contracted_volume_type if mapping else None
        contracted_volume_type_display = (
            mapping.get_contracted_volume_type_display() if mapping else None
        )

        # Calculate utilization metrics
        utilization_stats = self._calculate_utilization_stats(
            eps_data, contracted_volume
        )

        response_data = {
            "company_id": company.id,
            "company_name": company.company_name,
            "contracted_volume": contracted_volume,
            "contracted_volume_type": contracted_volume_type,
            "contracted_volume_type_display": contracted_volume_type_display,
            "eps_graph": eps_data,
            "utilization_stats": utilization_stats,
        }

        logger.success(
            f"EPS utilization calculated successfully for company {company.company_name}"
        )

        return Response(response_data, status=status.HTTP_200_OK)

    def _get_all_companies_eps_data(
        self, request, filter_enum, time_trunc, start_time, end_time
    ):
        """Get EPS data for all companies owned by the admin"""
        companies = Company.objects.filter(created_by=request.user)

        if not companies.exists():
            return Response(
                {
                    "message": "No companies found for this admin.",
                    "companies": [],
                },
                status=status.HTTP_200_OK,
            )

        companies_data = []

        for company in companies:
            # Get QRadar tenant IDs for this company
            qradar_tenant_ids = company.qradar_mappings.values_list(
                "qradar_tenant__id", flat=True
            )

            if not qradar_tenant_ids:
                # Add company with empty data if no QRadar tenants
                companies_data.append(
                    {
                        "company_id": company.id,
                        "company_name": company.company_name,
                        "contracted_volume": None,
                        "contracted_volume_type": None,
                        "contracted_volume_type_display": None,
                        "eps_graph": [],
                        "utilization_stats": self._get_empty_utilization_stats(),
                    }
                )
                continue

            # Build filter kwargs for EPS data
            filter_kwargs = {"domain_id__in": qradar_tenant_ids}
            if filter_enum == FilterType.CUSTOM_RANGE:
                filter_kwargs["created_at__range"] = (start_time, end_time)
            else:
                filter_kwargs["created_at__gte"] = start_time

            # Query EPS data with aggregation
            eps_data_raw = (
                IBMQradarEPS.objects.filter(**filter_kwargs)
                .annotate(interval=time_trunc)
                .values("interval")
                .annotate(average_eps=Avg("average_eps"), peak_eps=Max("peak_eps"))
                .order_by("interval")
            )

            # Format EPS data for response
            eps_data = self._format_eps_data(
                eps_data_raw, filter_enum, filter_kwargs, time_trunc
            )

            # Get contracted volume information
            mapping = TenantQradarMapping.objects.filter(company=company).first()
            contracted_volume = mapping.contracted_volume if mapping else None
            contracted_volume_type = mapping.contracted_volume_type if mapping else None
            contracted_volume_type_display = (
                mapping.get_contracted_volume_type_display() if mapping else None
            )

            # Calculate utilization metrics
            utilization_stats = self._calculate_utilization_stats(
                eps_data, contracted_volume
            )

            companies_data.append(
                {
                    "company_id": company.id,
                    "company_name": company.company_name,
                    "contracted_volume": contracted_volume,
                    "contracted_volume_type": contracted_volume_type,
                    "contracted_volume_type_display": contracted_volume_type_display,
                    "eps_graph": eps_data,
                    "utilization_stats": utilization_stats,
                }
            )

        logger.success(
            f"EPS utilization calculated successfully for {len(companies_data)} companies"
        )

        return Response(
            {
                "message": f"EPS utilization data retrieved for {len(companies_data)} companies",
                "total_companies": len(companies_data),
                "companies": companies_data,
            },
            status=status.HTTP_200_OK,
        )

    def _get_empty_utilization_stats(self):
        """Return empty utilization statistics"""
        return {
            "average_utilization_percentage": 0,
            "peak_utilization_percentage": 0,
            "total_data_points": 0,
            "over_limit_count": 0,
        }

    def _get_time_range_and_truncation(self, filter_enum, now, request):
        """Calculate time range and truncation based on filter type"""
        from pytz import timezone as pytz_timezone

        # Time range & truncation logic (similar to EPSGraphAPIView)
        if filter_enum == FilterType.TODAY:
            dubai_tz = pytz_timezone("Asia/Dubai")
            dubai_now = now.astimezone(dubai_tz)
            dubai_midnight = dubai_now.replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            start_time = dubai_midnight.astimezone(pytz_timezone("UTC"))
            time_trunc = TruncHour("created_at")
            end_time = None
        elif filter_enum == FilterType.WEEK:
            start_time = now - timedelta(days=6)
            time_trunc = TruncDay("created_at")
            end_time = None
        elif filter_enum == FilterType.MONTH:
            start_time = now - timedelta(days=28)
            time_trunc = TruncWeek("created_at")
            end_time = None
        # elif filter_enum == FilterType.QUARTER:
        #     start_of_current_month = now.replace(
        #         day=1, hour=0, minute=0, second=0, microsecond=0
        #     )
        #     if start_of_current_month.month >= 3:
        #         start_time = start_of_current_month.replace(
        #             month=start_of_current_month.month - 2
        #         )
        #     else:
        #         year = (
        #             start_of_current_month.year - 1
        #             if start_of_current_month.month <= 2
        #             else start_of_current_month.year
        #         )
        #         month = (
        #             start_of_current_month.month + 10
        #             if start_of_current_month.month <= 2
        #             else start_of_current_month.month - 2
        #         )
        #         start_time = start_of_current_month.replace(year=year, month=month)
        #     time_trunc = TruncMonth("created_at")
        #     end_time = None
        # elif filter_enum == FilterType.YEAR:
        #     start_time = now.replace(
        #         month=1, day=1, hour=0, minute=0, second=0, microsecond=0
        #     )
        #     time_trunc = TruncMonth("created_at")
        #     end_time = None
        elif filter_enum == FilterType.CUSTOM_RANGE:
            start_str = request.query_params.get("start_date")
            end_str = request.query_params.get("end_date")
            try:
                start_time = datetime.strptime(start_str, "%Y-%m-%d")
                end_time = datetime.strptime(end_str, "%Y-%m-%d") + timedelta(days=1)
                if start_time > end_time:
                    return (
                        Response(
                            {"error": "Start date must be before end date."},
                            status=status.HTTP_400_BAD_REQUEST,
                        ),
                        None,
                        None,
                    )
            except (ValueError, TypeError):
                return (
                    Response(
                        {"error": "Invalid custom date format. Use YYYY-MM-DD."},
                        status=status.HTTP_400_BAD_REQUEST,
                    ),
                    None,
                    None,
                )
            time_trunc = TruncDate("created_at")
        else:
            return (
                Response(
                    {"error": "Unsupported filter."},
                    status=status.HTTP_400_BAD_REQUEST,
                ),
                None,
                None,
            )

        return time_trunc, start_time, end_time

    def _format_eps_data(self, eps_data_raw, filter_enum, filter_kwargs, time_trunc):
        """Format EPS data with improved interval formatting"""
        eps_data = []
        for entry in eps_data_raw:
            interval_value = entry["interval"]

            # Find the peak row for detailed timing info
            peak_row = (
                IBMQradarEPS.objects.filter(**filter_kwargs)
                .annotate(interval=time_trunc)
                .filter(interval=interval_value, peak_eps=entry["peak_eps"])
                .order_by("created_at")
                .first()
            )
            peak_eps_time = (
                peak_row.created_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                if peak_row and peak_row.created_at
                else None
            )

            # Format interval string based on filter type
            if filter_enum == FilterType.TODAY:
                interval_str = entry["interval"].strftime("%Y-%m-%dT%H:%M:%SZ")
            elif filter_enum == FilterType.MONTH:
                week_num = len(eps_data) + 1
                interval_str = f"Week {week_num}"
            # elif filter_enum == FilterType.QUARTER:
            #     interval_str = entry["interval"].strftime("%B %Y")
            # elif filter_enum == FilterType.YEAR:
            #     interval_str = entry["interval"].strftime("%B")
            else:
                interval_str = entry["interval"].strftime("%Y-%m-%d")

            eps_data.append(
                {
                    "interval": interval_str,
                    "average_eps": float(
                        Decimal(entry["average_eps"] or 0).quantize(
                            Decimal("0.01"), rounding=ROUND_HALF_UP
                        )
                    ),
                    "peak_eps": float(
                        Decimal(entry["peak_eps"] or 0).quantize(
                            Decimal("0.01"), rounding=ROUND_HALF_UP
                        )
                    ),
                    "peak_eps_time": peak_eps_time,
                }
            )

        return eps_data

    def _calculate_utilization_stats(self, eps_data, contracted_volume):
        """Calculate utilization statistics"""
        if not eps_data or not contracted_volume:
            return {
                "average_utilization_percentage": 0,
                "peak_utilization_percentage": 0,
                "total_data_points": 0,
                "over_limit_count": 0,
            }

        average_values = [entry["average_eps"] for entry in eps_data]
        peak_values = [entry["peak_eps"] for entry in eps_data]

        avg_utilization = (
            (sum(average_values) / len(average_values) / contracted_volume) * 100
            if contracted_volume > 0
            else 0
        )
        max_peak_eps = max(peak_values) if peak_values else 0
        peak_utilization = (
            (max_peak_eps / contracted_volume) * 100 if contracted_volume > 0 else 0
        )
        over_limit_count = sum(1 for peak in peak_values if peak > contracted_volume)

        return {
            "average_utilization_percentage": round(avg_utilization, 2),
            "peak_utilization_percentage": round(peak_utilization, 2),
            "total_data_points": len(eps_data),
            "over_limit_count": over_limit_count,
        }


class CompanyToolsAPIView(APIView):
    """
    APIView to return integration tools for all companies or a specific company.
    Returns detailed information about each company's integrated tools including types and subtypes.
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsReadonlyAdminUser]

    def get(self, request):
        company_id = request.query_params.get("company_id")
        logger.info(
            f"Company tools requested by user: {request.user.username}, "
            f"company_id: {company_id if company_id else 'all companies'}"
        )

        try:
            if company_id:
                # Get tools for specific company
                try:
                    company = Company.objects.get(id=company_id)
                    companies = [company]
                except Company.DoesNotExist:
                    return Response(
                        {"error": "Company not found"},
                        status=status.HTTP_404_NOT_FOUND,
                    )
            else:
                # Get tools for all companies
                companies = Company.objects.all()
                if not companies.exists():
                    return Response(
                        {
                            "message": "No companies found.",
                            "companies": [],
                        },
                        status=status.HTTP_200_OK,
                    )

            # Calculate tools data for each company
            companies_tools_data = []
            for company in companies:
                company_tools_data = self._get_company_tools(company)
                companies_tools_data.append(company_tools_data)

            response_data = {
                "companies_count": len(companies),
                "companies": companies_tools_data,
            }

            logger.success(
                f"Company tools data retrieved successfully for {len(companies)} companies"
            )

            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error retrieving company tools: {str(e)}")
            return Response(
                {"error": "Internal server error while retrieving company tools."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _get_company_tools(self, company):
        """Get detailed tools information for a specific company"""
        tools = []

        # Get all integrations for this company
        for integration in company.integrations.all():
            # Determine the integration type name
            integration_type_name = None
            integration_type_id = integration.integration_type

            try:
                from integration.models import (
                    IntegrationTypes,
                    ItsmSubTypes,
                    SiemSubTypes,
                    SoarSubTypes,
                    ThreatIntelligenceSubTypes,
                )

                integration_type_name = IntegrationTypes(integration_type_id).label
            except (ValueError, AttributeError):
                integration_type_name = "Unknown"

            # Determine the subtype name and ID based on integration type
            sub_type_name = None

            if (
                integration_type_id == IntegrationTypes.SIEM_INTEGRATION
                and integration.siem_subtype
            ):
                integration.siem_subtype
                try:
                    sub_type_name = SiemSubTypes(integration.siem_subtype).label
                except (ValueError, AttributeError):
                    sub_type_name = "Unknown SIEM"

            elif (
                integration_type_id == IntegrationTypes.SOAR_INTEGRATION
                and integration.soar_subtype
            ):
                integration.soar_subtype
                try:
                    sub_type_name = SoarSubTypes(integration.soar_subtype).label
                except (ValueError, AttributeError):
                    sub_type_name = "Unknown SOAR"

            elif (
                integration_type_id == IntegrationTypes.ITSM_INTEGRATION
                and integration.itsm_subtype
            ):
                integration.itsm_subtype
                try:
                    sub_type_name = ItsmSubTypes(integration.itsm_subtype).label
                except (ValueError, AttributeError):
                    sub_type_name = "Unknown ITSM"

            elif (
                integration_type_id == IntegrationTypes.THREAT_INTELLIGENCE
                and integration.threat_intelligence_subtype
            ):
                integration.threat_intelligence_subtype
                try:
                    sub_type_name = ThreatIntelligenceSubTypes(
                        integration.threat_intelligence_subtype
                    ).label
                except (ValueError, AttributeError):
                    sub_type_name = "Unknown Threat Intelligence"

            tool_info = {
                "id": integration.id,
                "instance_name": integration.instance_name,
                "integration_type": integration_type_name,
                "sub_type": sub_type_name,
                "status": integration.status,
                "created_at": integration.created_at,
                "updated_at": integration.updated_at,
            }
            tools.append(tool_info)

        return {
            "company_id": company.id,
            "company_name": company.company_name,
            "tools_count": len(tools),
            "tools": tools,
        }


class APIVersionAPIView(APIView):
    """
    APIView to return the current API version information.
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsReadonlyAdminUser]

    @logger.catch
    def get(self, request):
        logger.info(f"API version requested by user: {request.user.username}")

        version_info = {
            "api_version": APIConstants.API_VERSION,
            "api_name": APIConstants.API_NAME,
            "api_description": APIConstants.API_DESCRIPTION,
            "status": "active",
        }

        logger.success(
            f"API version {APIConstants.API_VERSION} information returned successfully"
        )

        return Response(version_info, status=status.HTTP_200_OK)
