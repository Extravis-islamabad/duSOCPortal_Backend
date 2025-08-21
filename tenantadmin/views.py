# authentication/views.py
import re
from datetime import datetime

from django.db.models import Count, Q
from django.utils import timezone
from loguru import logger
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from authentication.models import User
from authentication.permissions import IsAdminUser
from common.constants import APIConstants, PaginationConstants
from tenant.cortex_soar_tasks import sync_soar_data
from tenant.ibm_qradar_tasks import sync_ibm_qradar_data
from tenant.itsm_tasks import sync_itsm
from tenant.models import (
    Company,
    CustomerEPS,
    DUCortexSOARIncidentFinalModel,
    IBMQradarAssests,
    IBMQradarAssetsGroup,
    SlaLevelChoices,
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
                "message": f"users under company '{company.company_name}' have been deactivated."
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
        companies = (
            Company.objects.filter(created_by=request.user)
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


class NonActiveTenantsAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        logger.info(
            f"Non-active tenant companies requested by: {request.user.username}"
        )

        # Step 1: Annotate companies with count of inactive tenants
        companies = (
            Company.objects.filter(created_by=request.user)
            .annotate(
                inactive_tenant_count=Count(
                    "tenants",
                    filter=Q(tenants__tenant__is_active=False),
                    distinct=True,
                )
            )
            .filter(inactive_tenant_count__gt=0)
            .order_by("id")
        )

        if not companies.exists():
            return Response(
                {"message": "No companies found with inactive tenants."},
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

        logger.success(f"Found {companies.count()} companies with inactive tenants.")

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
    permission_classes = [IsAdminUser]

    def get(self, request):
        company_id = request.query_params.get("company_id")
        logger.info(
            f"Assets summary requested by user: {request.user.username}, company_id: {company_id}"
        )

        try:
            if company_id:
                # Get assets for specific company
                try:
                    company = Company.objects.get(
                        id=company_id, created_by=request.user
                    )
                    companies = [company]
                except Company.DoesNotExist:
                    return Response(
                        {"error": "Company not found or unauthorized."},
                        status=status.HTTP_404_NOT_FOUND,
                    )
            else:
                # Get assets for all companies owned by this admin
                companies = Company.objects.filter(created_by=request.user)
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
        now_dt = timezone.now()

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

            # Bulk fetch asset groups for threshold determination
            all_group_ids = set()
            for asset in assets:
                if asset.group_ids:
                    all_group_ids.update(asset.group_ids)

            groups = IBMQradarAssetsGroup.objects.filter(db_id__in=all_group_ids)
            group_map = {g.db_id: g for g in groups}

            # Process each asset
            for asset in assets:
                # Determine if asset is reporting
                is_reporting = self._is_asset_reporting(asset, group_map, now_dt)

                if is_reporting:
                    company_active_assets += 1
                else:
                    company_no_reporting_assets += 1

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

    def _is_asset_reporting(self, asset, group_map, now_dt):
        """Determine if an asset is currently reporting based on last event time"""
        # Asset must be enabled to be considered reporting
        if not asset.enabled:
            return False

        # Asset must have last_event_time to be considered reporting
        if not asset.last_event_time:
            return False

        # Default threshold is 24 hours unless overridden by group description
        threshold_minutes = 24 * 60

        # Check if any group has a custom threshold
        if asset.group_ids:
            for gid in asset.group_ids:
                if gid in group_map and group_map[gid].description:
                    match = re.search(
                        r"(\d+)\s*hour", group_map[gid].description, re.IGNORECASE
                    )
                    if match:
                        threshold_minutes = int(match.group(1)) * 60
                        break

        # Check if last event time is within threshold
        try:
            last_event_timestamp = int(asset.last_event_time) / 1000
            last_event_time = datetime.utcfromtimestamp(last_event_timestamp)
            last_event_time = timezone.make_aware(last_event_time)
            time_diff_minutes = (now_dt - last_event_time).total_seconds() / 60
            return time_diff_minutes <= threshold_minutes
        except (ValueError, TypeError):
            return False


class IncidentPrioritySummaryAPIView(APIView):
    """
    APIView to return incident priority summary for all tenants or a specific company.
    Returns count of true positive and false positive incidents grouped by priority.
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

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
                    company = Company.objects.get(
                        id=company_id, created_by=request.user
                    )
                    companies = [company]
                except Company.DoesNotExist:
                    return Response(
                        {"error": "Company not found or unauthorized."},
                        status=status.HTTP_404_NOT_FOUND,
                    )
            else:
                # Get incidents for all companies owned by this admin
                companies = Company.objects.filter(created_by=request.user)
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


class APIVersionAPIView(APIView):
    """
    APIView to return the current API version information.
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

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
