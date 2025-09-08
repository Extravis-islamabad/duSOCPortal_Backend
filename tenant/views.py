import io
import json
import os
import time
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal

import pandas as pd
from django.conf import settings
from django.db.models import (
    Avg,
    Count,
    DurationField,
    ExpressionWrapper,
    F,
    Max,
    Min,
    Q,
    Sum,
)
from django.db.models.functions import TruncDate, TruncDay, TruncHour, TruncWeek
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.templatetags.static import static
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.timezone import make_aware
from loguru import logger
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from weasyprint import HTML

from authentication.permissions import IsAdminUser, IsTenant
from common.constants import FilterType, PaginationConstants
from common.modules.cyware import Cyware
from common.utils import extract_use_case
from integration.models import (
    CredentialTypes,
    Integration,
    IntegrationCredentials,
    IntegrationTypes,
    ItsmSubTypes,
    SiemSubTypes,
    SoarSubTypes,
    ThreatIntelligenceSubTypes,
)
from tenant.cortex_soar_tasks import sync_notes_for_incident
from tenant.ibm_qradar_tasks import sync_ibm_qradar_data
from tenant.models import (
    Alert,
    CorrelatedEventLog,
    CywareAlertDetails,
    CywareTenantAlertDetails,
    DailyClosureReasonLog,
    DailyEventCountLog,
    DailyEventLog,
    DateTimeStorage,
    DefaultSoarSlaMetric,
    DestinationAddressLog,
    DosEventLog,
    DUCortexSOARIncidentFinalModel,
    DuCortexSOARTenants,
    DuIbmQradarTenants,
    DuITSMFinalTickets,
    DuITSMTenants,
    DUSoarNotes,
    EventCountLog,
    FileTypeChoices,
    IBMQradarAssests,
    IBMQradarEPS,
    IBMQradarEventCollector,
    IBMQradarOffense,
    LastMonthAvgEpsLog,
    MonthlyAvgEpsLog,
    ReconEventLog,
    SlaLevelChoices,
    SoarTenantSlaMetric,
    SourceIPGeoLocation,
    SuspiciousEventLog,
    Tenant,
    TenantPermissionChoices,
    TenantQradarMapping,
    TenantRole,
    ThreatIntelligenceTenant,
    ThreatIntelligenceTenantAlerts,
    TopAlertEventLog,
    TopDestinationConnectionLog,
    TopDosEventLog,
    TotalEvents,
    TotalTrafficLog,
    WeeklyAvgEpsLog,
)
from tenant.serializers import (
    AlertSerializer,
    CywareAlertDetailsSerializer,
    CywareTenantAlertDetailsSerializer,
    DUCortexSOARIncidentSerializer,
    DuCortexSOARTenantsSerializer,
    DuIbmQradarTenantsSerializer,
    DuITSMTenantsSerializer,
    DuITSMTicketsSerializer,
    IBMQradarAssestsSerializer,
    IBMQradarEventCollectorSerializer,
    RecentIncidentsSerializer,
    SourceIPGeoLocationSerializer,
    TenantRoleSerializer,
)


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


class EventCollectorsListAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]
    """
    API endpoint to retrieve all records from the IBMQradarEventCollector table.
    """

    def get(self, request, *args, **kwargs):
        try:
            event_collectors = IBMQradarEventCollector.objects.all()
            serializer = IBMQradarEventCollectorSerializer(event_collectors, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"error": f"Failed to retrieve event collectors: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class DuITSMTenantsListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        tenants = DuITSMTenants.objects.all()
        serializer = DuITSMTenantsSerializer(tenants, many=True)
        return Response(serializer.data)


# test
class DuCortexSOARTenantsListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        tenants = DuCortexSOARTenants.objects.all()
        serializer = DuCortexSOARTenantsSerializer(tenants, many=True)
        return Response(serializer.data)


class TestView(APIView):
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [IsAdminUser]

    def get(self, request):
        sync_ibm_qradar_data()
        # sync_ibm_admin_eps.delay()
        # sync_successful_logons.delay()
        # sync_dos_event_counts()
        # sync_requests_for_soar()
        # sync_correlated_events_data(
        #     "svc.soc.portal", "SeonRx##0@55555", "10.225.148.146", 443, 3
        # )

        # sync_aep_entra_failures_data(
        #     "svc.soc.portal", "SeonRx##0@55555", "10.225.148.146", 443, 3
        # )

        # sync_allowed_outbound_data(
        #     "svc.soc.portal", "SeonRx##0@55555", "10.225.148.146", 443, 3
        # )
        # This will delete the tenants and cascade delete related incidents
        # sync_notes()
        # sync_ibm.delay()
        # sync_itsm_tickets_soar_ids.delay()
        # sync_daily_closure_reason_counts.delay()
        # sync_dos_event_counts.delay()
        # sync_suspicious_event_counts.delay()
        # sync_destination_address_counts.delay()
        # sync_total_traffic.delay()
        # sync_weekly_correlated_event_counts.delay()
        # sync_correlated_event_counts.delay()
        # sync_recon_event_counts.delay()
        # sync_ibm_event_counts.delay()
        # sync_threat_intel.delay()
        # sync_threat_intel_for_tenants.delay()
        # sync_threat_alert_details.delay()
        # with Cyware(
        #     base_url="https://du.cyware.com",
        #     access_key="c54d63c9-8c08-4921-adee-8a83a2112104",
        #     secret_key="24303184-4d71-4935-9608-24ffba93c8e0",
        # ) as cyware:
        #     data = cyware.get_list_groups()
        #     print(data)
        # sync_requests_for_soar.delay()
        # sync_itsm_tenants_tickets.delay()
        # sync_event_log_sources.delay()
        return Response({"message": "Hello, world!"})


class DateTimeStorageView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        """
        Retrieve the stored datetime value for the portal (single-record storage).
        Returns:
            200 OK with:
            - exists: bool
            - datetime_value: ISO 8601 datetime string or null
        """
        try:
            dt = DateTimeStorage.get_stored_datetime()
            if dt is None:
                return Response(
                    {"exists": False, "datetime_value": None}, status=status.HTTP_200_OK
                )
            return Response(
                {"exists": True, "datetime_value": dt}, status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f"Error retrieving DateTimeStorage: {str(e)}", exc_info=True)
            return Response(
                {"error": "Unable to retrieve stored datetime."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class GetTenantAssetsList(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        """
        Retrieve IBM QRadar assets with pagination

        Returns:
            {
                "count": filtered_count,
                "next": next_page_url,
                "previous": previous_page_url,
                "results": serialized_assets
            }
        """
        try:
            # Step 1: Validate tenant
            tenant = Tenant.objects.select_related("tenant").get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response(
                {"detail": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
            )

        try:
            # Step 2: Check for active SIEM integration
            siem_integrations = tenant.company.integrations.filter(
                integration_type=IntegrationTypes.SIEM_INTEGRATION,
                siem_subtype=SiemSubTypes.IBM_QRADAR,
                status=True,
            )
            if not siem_integrations.exists():
                return Response(
                    {"error": "No active SIEM integration configured for tenant."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Step 3: Get mapped collector IDs
            collector_ids = (
                TenantQradarMapping.objects.filter(company=tenant.company)
                .prefetch_related("event_collectors")
                .values_list("event_collectors__id", flat=True)
            )
            if not collector_ids:
                return Response(
                    {"detail": "No Event Collectors mapped to this tenant."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Base filter for tenant's assets
            base_filter = Q(event_collector_id__in=collector_ids)

            # Step 4: Apply request filters for the actual results
            filters = base_filter.copy()

            # Name filter
            if name := request.query_params.get("name"):
                filters &= Q(name__icontains=name)

            sort = request.query_params.get("sort", None)
            # ID filter
            if id_filter := request.query_params.get("id"):
                try:
                    filters &= Q(id=int(id_filter))
                except ValueError:
                    return Response(
                        {"error": "Invalid id format. Must be an integer."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # DB ID filter
            if db_id := request.query_params.get("db_id"):
                try:
                    filters &= Q(db_id=int(db_id))
                except ValueError:
                    return Response(
                        {"error": "Invalid db_id format. Must be an integer."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Log source type filter
            if log_source_type := request.query_params.get("log_source_type"):
                filters &= Q(log_source_type__name__icontains=log_source_type)

            # Enabled filter
            if enabled := request.query_params.get("enabled"):
                try:
                    filters &= Q(enabled=enabled.lower() == "true")
                except ValueError:
                    return Response(
                        {"error": "Invalid enabled format. Must be true or false."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Last event date filter
            last_event_filter = request.query_params.get("last_event_date")

            # Custom date range filtering (start_date and end_date)
            start_date = request.query_params.get("start_date")
            end_date = request.query_params.get("end_date")

            # Check if either date parameter is provided - both must be provided together
            if start_date or end_date:
                # Validate that both dates are provided
                if not (start_date and end_date):
                    return Response(
                        {
                            "error": "Both start_date and end_date must be provided together for date filtering."
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                try:
                    # Parse the dates
                    start_date_obj = self._parse_date(start_date)
                    if not start_date_obj:
                        raise ValueError(
                            f"Invalid start_date format: {start_date}. Use YYYY-MM-DD format."
                        )

                    end_date_obj = self._parse_date(end_date)
                    if not end_date_obj:
                        raise ValueError(
                            f"Invalid end_date format: {end_date}. Use YYYY-MM-DD format."
                        )

                    # Validate that start_date is not greater than end_date
                    if start_date_obj > end_date_obj:
                        return Response(
                            {"error": "start_date cannot be greater than end_date."},
                            status=status.HTTP_400_BAD_REQUEST,
                        )

                    # Apply date range filter on creation_date_converted at database level
                    filters &= Q(
                        creation_date_converted__range=[start_date_obj, end_date_obj]
                    )

                except ValueError as e:
                    return Response(
                        {"error": str(e)},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Average EPS filter
            if average_eps := request.query_params.get("average_eps"):
                try:
                    filters &= Q(average_eps=float(average_eps))
                except ValueError:
                    return Response(
                        {"error": "Invalid average_eps format. Must be a number."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Apply database-level status filtering first if status filter is provided
            status_filter = request.query_params.get("status")
            if status_filter:
                status_filter = status_filter.upper()
                if status_filter not in ["SUCCESS", "ERROR", "ALL"]:
                    return Response(
                        {
                            "error": "Invalid status value. Must be 'SUCCESS', 'ERROR', or 'ALL'."
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                # Use is_active field for status filtering
                if status_filter == "SUCCESS":
                    filtered_assets = list(
                        IBMQradarAssests.objects.filter(
                            filters & Q(is_active=True)
                        ).select_related("event_collector", "log_source_type")
                    )
                elif status_filter == "ERROR":
                    filtered_assets = list(
                        IBMQradarAssests.objects.filter(
                            filters & Q(is_active=False)
                        ).select_related("event_collector", "log_source_type")
                    )
                else:
                    return Response(
                        {"error": "Invalid status value. Must be 'SUCCESS', 'ERROR'."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            else:
                # No status filter - get all assets
                filtered_assets = list(
                    IBMQradarAssests.objects.filter(filters).select_related(
                        "event_collector", "log_source_type"
                    )
                )

            # Apply last event date filter if provided
            if last_event_filter:
                try:
                    filter_date = self._parse_date(last_event_filter)
                    filtered_assets = [
                        asset
                        for asset in filtered_assets
                        if asset.last_event_date_converted == filter_date
                    ]
                except ValueError as e:
                    return Response(
                        {"error": str(e)},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            sort_flag = False
            if sort:
                sort_flag = True
            filtered_assets.sort(
                key=lambda x: x.creation_date_converted or date.min,
                reverse=sort_flag,
            )

            # Pagination
            paginator = PageNumberPagination()
            paginator.page_size = PaginationConstants.PAGE_SIZE
            result_page = paginator.paginate_queryset(filtered_assets, request)

            # Serialize results using is_active field
            serialized_data = []
            for asset in result_page:
                asset_data = IBMQradarAssestsSerializer(asset).data
                serialized_data.append(asset_data)

            # Prepare response
            response_data = {
                "count": len(filtered_assets),
                "results": serialized_data,
            }

            # Add pagination links if needed
            if getattr(paginator, "page", None):
                response_data["next"] = paginator.get_next_link()
                response_data["previous"] = paginator.get_previous_link()

            return Response(response_data)

        except ValueError as e:
            logger.error(f"Value error in GetTenantAssetsList: {str(e)}")
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error in GetTenantAssetsList: {str(e)}", exc_info=True)
            return Response(
                {"error": f"An unexpected error occurred. {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

    def _parse_date(self, date_str):
        """Safe date parsing from string"""
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError:
            raise ValueError("Invalid date format")


class DownloadTenantAssetsExcel(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        """
        Download IBM QRadar assets as Excel file with all the same filtering options
        as GetTenantAssetsList endpoint.

        Query Parameters:
            Same as GetTenantAssetsList:
            - name: Filter by asset name
            - id: Filter by asset ID
            - db_id: Filter by database ID
            - log_source_type: Filter by log source type
            - enabled: Filter by enabled status (true/false)
            - last_event_date: Filter by last event date
            - start_date & end_date: Filter by creation date range (both required)
            - average_eps: Filter by average EPS
            - status: Filter by status (SUCCESS/ERROR/ALL)
            - sort: Sort by creation date (any value to enable reverse sort)

        Returns:
            Excel file download with filtered assets data
        """
        try:
            # Step 1: Validate tenant
            tenant = Tenant.objects.select_related("tenant").get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response(
                {"detail": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
            )

        try:
            # Step 2: Check for active SIEM integration
            siem_integrations = tenant.company.integrations.filter(
                integration_type=IntegrationTypes.SIEM_INTEGRATION,
                siem_subtype=SiemSubTypes.IBM_QRADAR,
                status=True,
            )
            if not siem_integrations.exists():
                return Response(
                    {"error": "No active SIEM integration configured for tenant."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Step 3: Get mapped collector IDs
            collector_ids = (
                TenantQradarMapping.objects.filter(company=tenant.company)
                .prefetch_related("event_collectors")
                .values_list("event_collectors__id", flat=True)
            )
            if not collector_ids:
                return Response(
                    {"detail": "No Event Collectors mapped to this tenant."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Base filter for tenant's assets
            base_filter = Q(event_collector_id__in=collector_ids)

            # Step 4: Apply request filters for the actual results
            filters = base_filter.copy()

            # Name filter
            if name := request.query_params.get("name"):
                filters &= Q(name__icontains=name)

            sort = request.query_params.get("sort", None)

            # ID filter
            if id_filter := request.query_params.get("id"):
                try:
                    filters &= Q(id=int(id_filter))
                except ValueError:
                    return Response(
                        {"error": "Invalid id format. Must be an integer."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # DB ID filter
            if db_id := request.query_params.get("db_id"):
                try:
                    filters &= Q(db_id=int(db_id))
                except ValueError:
                    return Response(
                        {"error": "Invalid db_id format. Must be an integer."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Log source type filter
            if log_source_type := request.query_params.get("log_source_type"):
                filters &= Q(log_source_type__name__icontains=log_source_type)

            # Enabled filter
            if enabled := request.query_params.get("enabled"):
                try:
                    filters &= Q(enabled=enabled.lower() == "true")
                except ValueError:
                    return Response(
                        {"error": "Invalid enabled format. Must be true or false."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Last event date filter
            last_event_filter = request.query_params.get("last_event_date")

            # Custom date range filtering (start_date and end_date)
            start_date = request.query_params.get("start_date")
            end_date = request.query_params.get("end_date")

            # Apply date filtering only if both dates are provided
            # If neither is provided, export all data without date filtering
            if start_date and end_date:
                try:
                    # Parse the dates
                    start_date_obj = self._parse_date(start_date)
                    if not start_date_obj:
                        raise ValueError(
                            f"Invalid start_date format: {start_date}. Use YYYY-MM-DD format."
                        )

                    end_date_obj = self._parse_date(end_date)
                    if not end_date_obj:
                        raise ValueError(
                            f"Invalid end_date format: {end_date}. Use YYYY-MM-DD format."
                        )

                    # Validate that start_date is not greater than end_date
                    if start_date_obj > end_date_obj:
                        return Response(
                            {"error": "start_date cannot be greater than end_date."},
                            status=status.HTTP_400_BAD_REQUEST,
                        )

                    # Apply date range filter on creation_date_converted at database level
                    filters &= Q(
                        creation_date_converted__range=[start_date_obj, end_date_obj]
                    )

                except ValueError as e:
                    return Response(
                        {"error": str(e)},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            elif start_date or end_date:
                # If only one date is provided, return an error
                return Response(
                    {
                        "error": "Both start_date and end_date must be provided together for date filtering, or omit both to export all data."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            # If neither start_date nor end_date is provided, no date filtering is applied
            # This will export all assets for the tenant

            # Average EPS filter
            if average_eps := request.query_params.get("average_eps"):
                try:
                    filters &= Q(average_eps=float(average_eps))
                except ValueError:
                    return Response(
                        {"error": "Invalid average_eps format. Must be a number."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Apply database-level status filtering first if status filter is provided
            status_filter = request.query_params.get("status")
            if status_filter:
                status_filter = status_filter.upper()
                if status_filter not in ["SUCCESS", "ERROR", "ALL"]:
                    return Response(
                        {
                            "error": "Invalid status value. Must be 'SUCCESS', 'ERROR', or 'ALL'."
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                # Use is_active field for status filtering
                if status_filter == "SUCCESS":
                    filtered_assets = list(
                        IBMQradarAssests.objects.filter(
                            filters & Q(is_active=True)
                        ).select_related("event_collector", "log_source_type")
                    )
                elif status_filter == "ERROR":
                    filtered_assets = list(
                        IBMQradarAssests.objects.filter(
                            filters & Q(is_active=False)
                        ).select_related("event_collector", "log_source_type")
                    )
                else:
                    return Response(
                        {"error": "Invalid status value. Must be 'SUCCESS', 'ERROR'."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            else:
                # No status filter - get all assets
                filtered_assets = list(
                    IBMQradarAssests.objects.filter(filters).select_related(
                        "event_collector", "log_source_type"
                    )
                )

            # Apply last event date filter if provided
            if last_event_filter:
                try:
                    filter_date = self._parse_date(last_event_filter)
                    filtered_assets = [
                        asset
                        for asset in filtered_assets
                        if asset.last_event_date_converted == filter_date
                    ]
                except ValueError as e:
                    return Response(
                        {"error": str(e)},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Sort assets
            sort_flag = False
            if sort:
                sort_flag = True
            filtered_assets.sort(
                key=lambda x: x.creation_date_converted or date.min,
                reverse=sort_flag,
            )

            # Check if there's data to export
            if not filtered_assets:
                return Response(
                    {"error": "No assets found with the specified filters."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Generate Excel file
            return self._generate_excel(filtered_assets, start_date, end_date)

        except Exception as e:
            logger.error(f"Error in DownloadTenantAssetsExcel: {str(e)}", exc_info=True)
            return Response(
                {"error": "An unexpected error occurred."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _parse_date(self, date_str):
        """Safe date parsing from string"""
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError:
            raise ValueError("Invalid date format")

    def _generate_excel(self, assets, start_date=None, end_date=None):
        """Generate Excel file with assets data"""
        try:
            # Prepare data for DataFrame
            data = []
            for asset in assets:
                # Format dates for better readability in Excel
                # Handle timestamp format (milliseconds since epoch)
                def format_timestamp_date(timestamp_value):
                    if timestamp_value:
                        try:
                            # If it's a timestamp in milliseconds
                            if isinstance(timestamp_value, (int, float)) or (
                                isinstance(timestamp_value, str)
                                and timestamp_value.isdigit()
                            ):
                                timestamp_seconds = int(timestamp_value) / 1000
                                return datetime.fromtimestamp(
                                    timestamp_seconds
                                ).strftime("%Y-%m-%d")
                            # If it's already a datetime object
                            elif hasattr(timestamp_value, "strftime"):
                                return timestamp_value.strftime("%Y-%m-%d")
                            # If it's a string that might be a timestamp
                            else:
                                return str(timestamp_value)
                        except (ValueError, TypeError, OSError):
                            return "N/A"
                    return "N/A"

                creation_time = format_timestamp_date(asset.creation_date)
                modified_time = format_timestamp_date(asset.modified_date)
                last_event_time = format_timestamp_date(asset.last_event_time)

                # Determine status based on is_active field
                status_value = "ACTIVE" if asset.is_active is True else "IN ACTIVE"

                data.append(
                    {
                        # "ID": asset.id,
                        "ID": asset.db_id,
                        "Name": asset.name or "N/A",
                        "Description": asset.description or "N/A",
                        "Event Collector": asset.event_collector.name
                        if asset.event_collector
                        else "N/A",
                        "Log Source Type": asset.log_source_type.name
                        if asset.log_source_type
                        else "N/A",
                        "Enabled": "Yes" if asset.enabled else "No",
                        "Status": status_value,
                        "Sub Status": asset.status,
                        "Average EPS": asset.average_eps,
                        # "Sending IP": asset.sending_ip or "N/A",
                        "Onboarding Date": creation_time,
                        "Modified Date": modified_time,
                        "Last Event Date": last_event_time,
                    }
                )

            # Create DataFrame
            df = pd.DataFrame(data)

            # Create Excel file in memory
            buffer = io.BytesIO()
            with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
                df.to_excel(writer, sheet_name="Tenant Assets", index=False)

                # Get the worksheet to apply formatting
                worksheet = writer.sheets["Tenant Assets"]

                # Auto-adjust column widths
                for column in worksheet.columns:
                    max_length = 0
                    column_letter = column[0].column_letter
                    for cell in column:
                        try:
                            if cell.value and len(str(cell.value)) > max_length:
                                max_length = len(str(cell.value))
                        except Exception:
                            logger.error(".")
                    adjusted_width = min(max_length + 2, 50)  # Prevent too wide columns
                    worksheet.column_dimensions[column_letter].width = adjusted_width

                # Add header formatting
                from openpyxl.styles import Alignment, Font, PatternFill

                header_font = Font(bold=True, color="FFFFFF")
                header_fill = PatternFill(
                    start_color="366092", end_color="366092", fill_type="solid"
                )
                header_alignment = Alignment(horizontal="center", vertical="center")

                for cell in worksheet[1]:
                    cell.font = header_font
                    cell.fill = header_fill
                    cell.alignment = header_alignment

            buffer.seek(0)

            # Generate filename
            filename = f"tenant_assets_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            if start_date and end_date:
                filename = f"tenant_assets_{start_date}_to_{end_date}"
            filename += ".xlsx"

            response = HttpResponse(
                buffer.getvalue(),
                content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
            response["Content-Disposition"] = f'attachment; filename="{filename}"'
            return response

        except Exception as e:
            logger.error(f"Error generating Excel: {str(e)}")
            return Response(
                {"error": "Failed to generate Excel file."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class GetTenantAssetsStats(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        """
        Return asset statistics:
        - total_assets
        - success_assets
        - error_assets
        """
        try:
            tenant = Tenant.objects.select_related("tenant").get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response(
                {"detail": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
            )

        try:
            siem_integrations = tenant.company.integrations.filter(
                integration_type=IntegrationTypes.SIEM_INTEGRATION,
                siem_subtype=SiemSubTypes.IBM_QRADAR,
                status=True,
            )
            if not siem_integrations.exists():
                return Response(
                    {"error": "No active SIEM integration configured for tenant."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            collector_ids = (
                TenantQradarMapping.objects.filter(company=tenant.company)
                .prefetch_related("event_collectors")
                .values_list("event_collectors__id", flat=True)
            )
            if not collector_ids:
                return Response(
                    {"detail": "No Event Collectors mapped to this tenant."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            base_queryset = IBMQradarAssests.objects.filter(
                event_collector_id__in=collector_ids
            )

            total_assets = base_queryset.count()
            success_assets = base_queryset.filter(status__iexact="success").count()
            error_assets = base_queryset.filter(status__iexact="error").count()
            na_assets = base_queryset.filter(status__iexact="na").count()
            disabled_assets = base_queryset.filter(status__iexact="disabled").count()
            warning_assets = base_queryset.filter(status__iexact="warn").count()
            return Response(
                {
                    "total_assets": total_assets,
                    "success_assets": success_assets,
                    "error_assets": error_assets,
                    "disabled_assets": disabled_assets,
                    "na_assets": na_assets,
                    "warning_assets": warning_assets,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Error in GetTenantAssetsStats: {str(e)}")
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class TenantITSMTicketsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        """
        Retrieve ITSM tickets filtered by:
        - ITSM tenant IDs
        - Optional query parameters: account_name, db_id, id, subject, status, created_by, start_date, end_date

        Query Parameters:
            account_name (str): Partial match on account_name (case-insensitive)
            db_id (int): Exact match on db_id
            id (int): Exact match on id
            subject (str): Partial match on subject (case-insensitive)
            status (str): Exact match on status (case-insensitive)
            created_by (str): Partial match on created_by_name (case-insensitive)
            start_date (YYYY-MM-DD): Tickets with creation_date on or after this date
            end_date (YYYY-MM-DD): Tickets with creation_date on or before this date (inclusive of the entire day)

        Returns:
            Paginated response with count, next, previous, and results
        """
        try:
            # Step 1: Validate tenant
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response(
                {"error": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
            )

        try:
            # Step 2: Check for active ITSM integration
            itsm_integrations = tenant.company.integrations.filter(
                integration_type=IntegrationTypes.ITSM_INTEGRATION,
                itsm_subtype=ItsmSubTypes.MANAGE_ENGINE,
                status=True,
            )
            if not itsm_integrations.exists():
                return Response(
                    {"error": "No active ITSM integration configured for tenant."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Step 3: Get ITSM tenant IDs
            itsm_tenant_ids = tenant.company.itsm_tenants.values_list("id", flat=True)
            if not itsm_tenant_ids:
                return Response(
                    {"error": "No ITSM tenants found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Step 4: Build filters
            filters = Q(itsm_tenant__in=itsm_tenant_ids)

            # Account name filter
            account_name = request.query_params.get("account_name")
            if account_name:
                filters &= Q(account_name__icontains=account_name)

            # DB ID filter
            db_id = request.query_params.get("db_id")
            if db_id:
                try:
                    filters &= Q(db_id=int(db_id))
                except ValueError:
                    return Response(
                        {"error": "Invalid db_id format. Must be an integer."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # ID filter
            id_filter = request.query_params.get("id")
            if id_filter:
                try:
                    filters &= Q(id=int(id_filter))
                except ValueError:
                    return Response(
                        {"error": "Invalid id format. Must be an integer."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Subject filter
            subject_filter = request.query_params.get("subject")
            if subject_filter:
                filters &= Q(subject__icontains=subject_filter)

            # Status filter
            status_filter = request.query_params.get("status")
            if status_filter:
                filters &= Q(status__iexact=status_filter)

            # Created by filter
            created_by_filter = request.query_params.get("created_by")
            if created_by_filter:
                filters &= Q(created_by_name__icontains=created_by_filter)

            # Parse start and end dates from query
            query_date_format = "%Y-%m-%d"
            start_date = None
            end_date = None
            start_date_str = request.query_params.get("start_date")
            end_date_str = request.query_params.get("end_date")

            if start_date_str:
                try:
                    start_date = datetime.strptime(start_date_str, query_date_format)
                except ValueError:
                    return Response(
                        {"error": "Invalid start_date format. Use YYYY-MM-DD."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if end_date_str:
                try:
                    end_date = datetime.strptime(end_date_str, query_date_format)
                    # Extend end_date to the end of the day
                    end_date = end_date.replace(
                        hour=23, minute=59, second=59, microsecond=999999
                    )
                except ValueError:
                    return Response(
                        {"error": "Invalid end_date format. Use YYYY-MM-DD."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if start_date and end_date and end_date < start_date:
                return Response(
                    {"error": "end_date must be on or after start_date."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Fetch all matching tickets
            tickets = DuITSMFinalTickets.objects.filter(filters).order_by(
                "-creation_date"
            )

            # Apply date filtering manually since creation_date is a CharField
            if start_date or end_date:
                filtered = []
                db_date_format = "%b %d, %Y %I:%M %p"  # e.g., "Sep 30, 2024 11:36 AM"
                for ticket in tickets:
                    try:
                        ticket_date = datetime.strptime(
                            ticket.creation_date, db_date_format
                        )
                        if (not start_date or ticket_date >= start_date) and (
                            not end_date or ticket_date <= end_date
                        ):
                            filtered.append(ticket)
                    except ValueError as e:
                        logger.warning(
                            f"Skipping ticket with invalid creation_date '{ticket.creation_date}': {str(e)}"
                        )
                        continue  # Skip malformed dates
                tickets = filtered

            # Step 5: Pagination
            paginator = PageNumberPagination()
            paginator.page_size = PaginationConstants.PAGE_SIZE
            paginated_tickets = paginator.paginate_queryset(tickets, request)

            # Step 6: Serialize and return response
            serializer = DuITSMTicketsSerializer(paginated_tickets, many=True)
            return paginator.get_paginated_response(serializer.data)

        except Exception as e:
            logger.error(f"Error in TenantITSMTicketsView: {str(e)}")
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class TenantITSMTicketDetailView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request, db_id):
        """
        Get a single ITSM ticket by db_id for the authenticated tenant.
        """
        try:
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response(
                {"error": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
            )

        # Get the ITSM tenant IDs linked to this company
        itsm_tenant_ids = tenant.company.itsm_tenants.values_list("id", flat=True)

        try:
            ticket = DuITSMFinalTickets.objects.get(
                db_id=db_id, itsm_tenant_id__in=itsm_tenant_ids
            )
        except DuITSMFinalTickets.DoesNotExist:
            return Response(
                {"error": f"No ticket found with db_id={db_id} for your tenant."},
                status=404,
            )

        serializer = DuITSMTicketsSerializer(ticket, context={"request": request})
        return Response(serializer.data, status=200)


class TenantCortexSOARIncidentsAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        try:
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)
        soar_integrations = tenant.integrations.filter(
            integration_type=IntegrationTypes.SOAR_INTEGRATION,
            soar_subtype=SoarSubTypes.CORTEX_SOAR,
            status=True,
        )
        if not soar_integrations.exists():
            return Response(
                {"error": "No active SOAR integration configured for tenant."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        soar_tenants = tenant.soar_tenants.all()
        soar_ids = [t.id for t in soar_tenants]

        incidents = DUCortexSOARIncidentFinalModel.objects.filter(
            cortex_soar_tenant__in=soar_ids
        )
        paginator = PageNumberPagination()
        paginator.page_size = PaginationConstants.PAGE_SIZE
        paginated_incidents = paginator.paginate_queryset(incidents, request)
        serializer = DUCortexSOARIncidentSerializer(paginated_incidents, many=True)
        return paginator.get_paginated_response(serializer.data)


class TypeDistributionView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        # Extract tenant_id from X-Tenant-ID header, default to 'CDC-Mey-Tabreeds'
        try:
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)

        soar_integrations = tenant.company.integrations.filter(
            integration_type=IntegrationTypes.SOAR_INTEGRATION,
            soar_subtype=SoarSubTypes.CORTEX_SOAR,
            status=True,
        )
        if not soar_integrations.exists():
            return Response(
                {"error": "No active SOAR integration configured for tenant."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        soar_tenants = tenant.company.soar_tenants.all()
        if not soar_tenants:
            return Response({"error": "No SOAR tenants found."}, status=404)

        soar_ids = [t.id for t in soar_tenants]

        if not soar_ids:
            return Response({"error": "No SOAR tenants found."}, status=404)
        filters = Q()
        try:
            # Handle date filtering
            filter_type = request.query_params.get("filter_type")
            start_date = request.query_params.get("start_date")
            end_date = request.query_params.get("end_date")
            db_timezone = timezone.get_fixed_timezone(240)
            now = timezone.now().astimezone(db_timezone)
            if start_date and end_date:
                try:
                    if not isinstance(start_date, str) or not isinstance(end_date, str):
                        return Response(
                            {
                                "error": "start_date and end_date must be strings in YYYY-MM-DD format."
                            },
                            status=400,
                        )

                    start_date = timezone.make_aware(
                        datetime.strptime(start_date, "%Y-%m-%d"), timezone=db_timezone
                    ).replace(hour=0, minute=0, second=0, microsecond=0)

                    end_date = timezone.make_aware(
                        datetime.strptime(end_date, "%Y-%m-%d"), timezone=db_timezone
                    ).replace(hour=23, minute=59, second=59, microsecond=999999)

                    filters &= Q(occured__gte=start_date) & Q(occured__lte=end_date)
                except ValueError:
                    return Response(
                        {"error": "Invalid date format. Use YYYY-MM-DD."}, status=400
                    )

            elif filter_type:
                try:
                    filter_type = FilterType(int(filter_type))
                    if filter_type == FilterType.TODAY:
                        start_date = now.replace(
                            hour=0, minute=0, second=0, microsecond=0
                        )
                        end_date = now.replace(
                            hour=23, minute=59, second=59, microsecond=999999
                        )
                    elif filter_type == FilterType.WEEK:
                        start_date = now - timedelta(days=now.weekday())
                        start_date = start_date.replace(
                            hour=0, minute=0, second=0, microsecond=0
                        )
                        end_date = now.replace(
                            hour=23, minute=59, second=59, microsecond=999999
                        )
                    elif filter_type == FilterType.MONTH:
                        start_date = now.replace(
                            day=1, hour=0, minute=0, second=0, microsecond=0
                        )
                        end_date = now.replace(
                            hour=23, minute=59, second=59, microsecond=999999
                        )
                    filters &= Q(occured__gte=start_date) & Q(occured__lte=end_date)

                except Exception as e:
                    return Response(
                        {"error": f"Invalid filter_type: {str(e)}"}, status=400
                    )

            # Query type distribution using Django ORM
            type_data = (
                DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids
                )
                .filter(filters)
                .values("qradar_category")
                .annotate(count=Count("id"))
                .order_by("-count")
                .exclude(
                    qradar_category__isnull=True
                )  # Exclude NULL qradarcategory values
            )

            # Transform data to match Flask output
            result = [
                {"name": item["qradar_category"], "value": item["count"]}
                for item in type_data
            ]

            return Response({"typeDistribution": result}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error("Error in TypeDistributionView: %s", str(e))
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class OwnerDistributionView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        try:
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)

        soar_integrations = tenant.company.integrations.filter(
            integration_type=IntegrationTypes.SOAR_INTEGRATION,
            soar_subtype=SoarSubTypes.CORTEX_SOAR,
            status=True,
        )
        if not soar_integrations.exists():
            return Response(
                {"error": "No active SOAR integration configured for tenant."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        soar_tenants = tenant.company.soar_tenants.all()
        if not soar_tenants:
            return Response({"error": "No SOAR tenants found."}, status=404)

        soar_ids = [t.id for t in soar_tenants]

        if not soar_ids:
            return Response({"error": "No SOAR tenants found."}, status=404)

        try:
            # Fetch owner counts excluding null
            owner_counts = (
                DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids
                )
                .exclude(owner__isnull=True)
                .values("owner")
                .annotate(count=Count("owner"))
                .order_by("-count")
            )

            owner_data = [
                {"name": item["owner"], "value": item["count"]} for item in owner_counts
            ]

            # Count unassigned
            unassigned_count = DUCortexSOARIncidentFinalModel.objects.filter(
                cortex_soar_tenant__in=soar_ids, owner__isnull=True
            ).count()

            if unassigned_count > 0:
                owner_data.append({"name": "Unassigned", "value": unassigned_count})

            return Response(
                {"ownerDistribution": owner_data}, status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class DashboardView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        try:
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)

        soar_integrations = tenant.company.integrations.filter(
            integration_type=IntegrationTypes.SOAR_INTEGRATION,
            soar_subtype=SoarSubTypes.CORTEX_SOAR,
            status=True,
        )
        if not soar_integrations.exists():
            return Response(
                {"error": "No active SOAR integration configured for tenant."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        soar_tenants = tenant.company.soar_tenants.all()
        if not soar_tenants:
            return Response({"error": "No SOAR tenants found."}, status=404)

        soar_ids = [t.id for t in soar_tenants]
        filters = request.query_params.get("filters", "")
        filter_list = (
            [f.strip() for f in filters.split(",") if f.strip()] if filters else []
        )

        # Get filter_type from query params
        filter_type_param = request.query_params.get("filter_type")
        filter_type = None
        if filter_type_param:
            try:
                filter_type_value = int(filter_type_param)
                filter_type = FilterType(filter_type_value)
            except (ValueError, KeyError):
                return Response(
                    {"error": "Invalid filter_type value."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # When no filter_type is provided, do not include trend in the response
        include_trend = filter_type is not None

        # Determine date range based on filter_type
        now = timezone.now()
        start_date = None
        end_date = None

        if filter_type:
            if filter_type == FilterType.TODAY:
                start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
            elif filter_type == FilterType.WEEK:
                start_date = now - timedelta(days=7)
            elif filter_type == FilterType.MONTH:
                start_date = now - timedelta(days=30)
            elif filter_type == FilterType.CUSTOM_RANGE:
                start_date = self._parse_date(request.query_params.get("start_date"))
                end_date = self._parse_date(request.query_params.get("end_date"))
                if not start_date or not end_date:
                    return Response(
                        {
                            "error": "Custom range requires both start_date and end_date."
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

        try:
            # Base filters for True Positives (Ready incidents with all required fields)
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

            # Base filters for False Positives (Done incidents)
            false_positive_filters = Q(cortex_soar_tenant__in=soar_ids) & Q(
                itsm_sync_status__iexact="Done"
            )

            total_incident_filters = true_positive_filters | false_positive_filters

            # Apply date range filters if provided
            if start_date or end_date:
                date_filter = Q()
                if start_date:
                    date_filter &= Q(created__date__gte=start_date)
                if end_date:
                    date_filter &= Q(created__date__lte=end_date)

                true_positive_filters &= date_filter
                false_positive_filters &= date_filter
                total_incident_filters &= date_filter

            # Additional filters from query params
            if incident_id := request.query_params.get("incident_id"):
                try:
                    incident_id = int(incident_id)
                    true_positive_filters &= Q(id=incident_id)
                    false_positive_filters &= Q(id=incident_id)
                    total_incident_filters &= Q(id=incident_id)
                except ValueError:
                    return Response(
                        {"error": "Invalid incident_id format. Must be an integer."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if owner := request.query_params.get("owner"):
                true_positive_filters &= Q(owner__icontains=owner)
                # False positives don't typically have owners, so we don't filter them

            if priority := request.query_params.get("priority"):
                true_positive_filters &= Q(incident_priority__iexact=priority)

            if status_filter := request.query_params.get("status"):
                try:
                    status_value = int(status_filter)
                    true_positive_filters &= Q(status=status_value)
                except ValueError:
                    return Response(
                        {
                            "error": "Invalid status value. Must be 1 (open) or 2 (closed)."
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Date calculations
            today = timezone.now().date()

            dashboard_data = {}

            # Total Incidents (True Positives + False Positives only)
            if not filter_list or "total_incidents" in filter_list:
                # Using the specified query structure for total incidents with date filtering
                total_incidents_query = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids,
                    status__in=["1", "2"],
                    itsm_sync_status__in=["Done", "Ready"],
                    owner__isnull=False,
                    owner__gt="",
                    incident_tta__isnull=False,
                    incident_ttn__isnull=False,
                    incident_ttdn__isnull=False,
                    incident_priority__isnull=False,
                    incident_priority__gt="",
                )

                # Apply date filters if provided
                if start_date or end_date:
                    if start_date:
                        if filter_type == FilterType.TODAY:
                            total_incidents_query = total_incidents_query.filter(
                                created__date=start_date.date()
                            )
                        else:
                            total_incidents_query = total_incidents_query.filter(
                                created__date__gte=start_date.date()
                                if hasattr(start_date, "date")
                                else start_date
                            )
                    if end_date:
                        total_incidents_query = total_incidents_query.filter(
                            created__date__lte=end_date.date()
                            if hasattr(end_date, "date")
                            else end_date
                        )

                total_incidents = total_incidents_query.count()

                if include_trend:
                    # Create new query for trend calculation with the updated query structure
                    trend_filters = Q(
                        cortex_soar_tenant__in=soar_ids,
                        status__in=["1", "2"],
                        itsm_sync_status__in=["Done", "Ready"],
                        owner__isnull=False,
                        owner__gt="",
                        incident_tta__isnull=False,
                        incident_ttn__isnull=False,
                        incident_ttdn__isnull=False,
                        incident_priority__isnull=False,
                        incident_priority__gt="",
                    )
                    (
                        current_count,
                        previous_count,
                        trend_period,
                    ) = self._calculate_trend_comparison(
                        trend_filters, filter_type, start_date, end_date
                    )

                    percent_change = self._calculate_percentage_change(
                        current_count, previous_count, trend_period
                    )
                else:
                    percent_change = None

                # Calculate new incidents for today using the updated query structure
                new_incidents = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids,
                    status__in=["1", "2"],
                    itsm_sync_status__in=["Done", "Ready"],
                    owner__isnull=False,
                    owner__gt="",
                    incident_tta__isnull=False,
                    incident_ttn__isnull=False,
                    incident_ttdn__isnull=False,
                    incident_priority__isnull=False,
                    incident_priority__gt="",
                    created__date=today,
                ).count()

                dashboard_data["total_incidents"] = {
                    "count": total_incidents,
                    "change": percent_change,
                    "new": new_incidents,
                }

            # Open Incidents based on status=1
            if not filter_list or "open" in filter_list:
                # Using the specified query structure for open incidents with date filtering
                open_incidents_query = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids,
                    status="1",
                    itsm_sync_status__in=["Done", "Ready"],
                    owner__isnull=False,
                    owner__gt="",
                    incident_tta__isnull=False,
                    incident_ttn__isnull=False,
                    incident_ttdn__isnull=False,
                    incident_priority__isnull=False,
                    incident_priority__gt="",
                )

                # Apply date filters if provided
                if start_date or end_date:
                    if start_date:
                        if filter_type == FilterType.TODAY:
                            open_incidents_query = open_incidents_query.filter(
                                created__date=start_date.date()
                            )
                        else:
                            open_incidents_query = open_incidents_query.filter(
                                created__date__gte=start_date.date()
                                if hasattr(start_date, "date")
                                else start_date
                            )
                    if end_date:
                        open_incidents_query = open_incidents_query.filter(
                            created__date__lte=end_date.date()
                            if hasattr(end_date, "date")
                            else end_date
                        )

                open_count = open_incidents_query.count()

                # Calculate trend based on filter type for open incidents using the updated query structure
                if include_trend:
                    trend_filters = Q(
                        cortex_soar_tenant__in=soar_ids,
                        status="1",
                        itsm_sync_status__in=["Done", "Ready"],
                        owner__isnull=False,
                        owner__gt="",
                        incident_tta__isnull=False,
                        incident_ttn__isnull=False,
                        incident_ttdn__isnull=False,
                        incident_priority__isnull=False,
                        incident_priority__gt="",
                    )
                    (
                        current_count,
                        previous_count,
                        trend_period,
                    ) = self._calculate_trend_comparison(
                        trend_filters, filter_type, start_date, end_date
                    )

                    percent_change = self._calculate_percentage_change(
                        current_count, previous_count, trend_period
                    )
                else:
                    percent_change = None

                dashboard_data["open"] = {"count": open_count, "change": percent_change}

            # Closed Incidents based on status=2
            if not filter_list or "closed" in filter_list:
                # Using the specified query structure for closed incidents with date filtering
                closed_incidents_query = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids,
                    status="2",
                    itsm_sync_status__in=["Done", "Ready"],
                    owner__isnull=False,
                    owner__gt="",
                    incident_tta__isnull=False,
                    incident_ttn__isnull=False,
                    incident_ttdn__isnull=False,
                    incident_priority__isnull=False,
                    incident_priority__gt="",
                )

                # Apply date filters if provided
                if start_date or end_date:
                    if start_date:
                        if filter_type == FilterType.TODAY:
                            closed_incidents_query = closed_incidents_query.filter(
                                created__date=start_date.date()
                            )
                        else:
                            closed_incidents_query = closed_incidents_query.filter(
                                created__date__gte=start_date.date()
                                if hasattr(start_date, "date")
                                else start_date
                            )
                    if end_date:
                        closed_incidents_query = closed_incidents_query.filter(
                            created__date__lte=end_date.date()
                            if hasattr(end_date, "date")
                            else end_date
                        )

                closed_count = closed_incidents_query.count()

                # Calculate trend based on filter type for closed incidents using the updated query structure
                if include_trend:
                    trend_filters = Q(
                        cortex_soar_tenant__in=soar_ids,
                        status="2",
                        itsm_sync_status__in=["Done", "Ready"],
                        owner__isnull=False,
                        owner__gt="",
                        incident_tta__isnull=False,
                        incident_ttn__isnull=False,
                        incident_ttdn__isnull=False,
                        incident_priority__isnull=False,
                        incident_priority__gt="",
                    )
                    (
                        current_count,
                        previous_count,
                        trend_period,
                    ) = self._calculate_trend_comparison(
                        trend_filters, filter_type, start_date, end_date
                    )

                    percent_change = self._calculate_percentage_change(
                        current_count, previous_count, trend_period
                    )
                else:
                    percent_change = None

                dashboard_data["closed"] = {
                    "count": closed_count,
                    "change": percent_change,
                }

            # False Positives (Done incidents)
            if not filter_list or "falsePositives" in filter_list:
                # Using the specified query structure for false positives with date filtering
                fp_query = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids,
                    itsm_sync_status="Done",
                    owner__isnull=False,
                    owner__gt="",
                    incident_tta__isnull=False,
                    incident_ttn__isnull=False,
                    incident_ttdn__isnull=False,
                    incident_priority__isnull=False,
                    incident_priority__gt="",
                )

                # Apply date filters if provided
                if start_date or end_date:
                    if start_date:
                        if filter_type == FilterType.TODAY:
                            fp_query = fp_query.filter(created__date=start_date.date())
                        else:
                            fp_query = fp_query.filter(
                                created__date__gte=start_date.date()
                                if hasattr(start_date, "date")
                                else start_date
                            )
                    if end_date:
                        fp_query = fp_query.filter(
                            created__date__lte=end_date.date()
                            if hasattr(end_date, "date")
                            else end_date
                        )

                fp_count = fp_query.count()

                # Calculate trend based on filter type for false positives using the updated query structure
                if include_trend:
                    trend_filters = Q(
                        cortex_soar_tenant__in=soar_ids,
                        itsm_sync_status="Done",
                        owner__isnull=False,
                        owner__gt="",
                        incident_tta__isnull=False,
                        incident_ttn__isnull=False,
                        incident_ttdn__isnull=False,
                        incident_priority__isnull=False,
                        incident_priority__gt="",
                    )
                    (
                        current_fp,
                        previous_fp,
                        trend_period,
                    ) = self._calculate_trend_comparison(
                        trend_filters, filter_type, start_date, end_date
                    )

                    percent_change = self._calculate_percentage_change(
                        current_fp, previous_fp, trend_period
                    )
                else:
                    percent_change = None

                dashboard_data["falsePositives"] = {
                    "count": fp_count,
                    "change": percent_change,
                }

            # True Positives (Ready incidents with all required fields)
            if not filter_list or "truePositives" in filter_list:
                # Using the specified query structure for true positives with date filtering
                tp_query = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids,
                    itsm_sync_status="Ready",
                    owner__isnull=False,
                    owner__gt="",
                    incident_tta__isnull=False,
                    incident_ttn__isnull=False,
                    incident_ttdn__isnull=False,
                    incident_priority__isnull=False,
                    incident_priority__gt="",
                )

                # Apply date filters if provided
                if start_date or end_date:
                    if start_date:
                        if filter_type == FilterType.TODAY:
                            tp_query = tp_query.filter(created__date=start_date.date())
                        else:
                            tp_query = tp_query.filter(
                                created__date__gte=start_date.date()
                                if hasattr(start_date, "date")
                                else start_date
                            )
                    if end_date:
                        tp_query = tp_query.filter(
                            created__date__lte=end_date.date()
                            if hasattr(end_date, "date")
                            else end_date
                        )

                tp_count = tp_query.count()

                # Calculate trend based on filter type for true positives using the updated query structure
                if include_trend:
                    trend_filters = Q(
                        cortex_soar_tenant__in=soar_ids,
                        itsm_sync_status="Ready",
                        owner__isnull=False,
                        owner__gt="",
                        incident_tta__isnull=False,
                        incident_ttn__isnull=False,
                        incident_ttdn__isnull=False,
                        incident_priority__isnull=False,
                        incident_priority__gt="",
                    )
                    (
                        current_tp,
                        previous_tp,
                        trend_period,
                    ) = self._calculate_trend_comparison(
                        trend_filters, filter_type, start_date, end_date
                    )

                    percent_change = self._calculate_percentage_change(
                        current_tp, previous_tp, trend_period
                    )
                else:
                    percent_change = None

                dashboard_data["truePositives"] = {
                    "count": tp_count,
                    "change": percent_change,
                }

            # OPTIONAL: Add incomplete incidents count for visibility
            if not filter_list or "incompleteIncidents" in filter_list:
                incomplete_filters = (
                    Q(cortex_soar_tenant__in=soar_ids)
                    & Q(itsm_sync_status__iexact="Ready")
                    & (
                        Q(owner__isnull=True)
                        | Q(owner__exact="")
                        | Q(incident_tta__isnull=True)
                        | Q(incident_ttn__isnull=True)
                        | Q(incident_ttdn__isnull=True)
                        | Q(incident_priority__isnull=True)
                        | Q(incident_priority__exact="")
                    )
                )

                # Apply date range filters if provided
                if start_date or end_date:
                    date_filter = Q()
                    if start_date:
                        date_filter &= Q(created__date__gte=start_date)
                    if end_date:
                        date_filter &= Q(created__date__lte=end_date)
                    incomplete_filters &= date_filter

                incomplete_count = DUCortexSOARIncidentFinalModel.objects.filter(
                    incomplete_filters
                ).count()

                dashboard_data["incompleteIncidents"] = {
                    "count": incomplete_count,
                    "description": "Ready incidents with missing required fields",
                }

            return Response(dashboard_data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error("Error in DashboardView: %s", str(e))
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _calculate_trend_comparison(
        self, base_filters, filter_type, start_date, end_date
    ):
        """Calculate current and previous period counts for trend comparison"""
        now = timezone.now().date()

        # Return N/A for custom date range filters
        if filter_type == FilterType.CUSTOM_RANGE:
            return 0, 0, "N/A"

        if not filter_type:
            # Default to week comparison if no filter_type
            current_start = now - timedelta(days=6)
            current_end = now
            previous_start = now - timedelta(days=13)
            previous_end = now - timedelta(days=7)
            period = "week"
        elif filter_type == FilterType.TODAY:
            # Compare today with yesterday
            current_start = current_end = now
            previous_start = previous_end = now - timedelta(days=1)
            period = "day"
        elif filter_type == FilterType.WEEK:
            # Compare this week with previous week
            current_start = now - timedelta(days=6)
            current_end = now
            previous_start = now - timedelta(days=13)
            previous_end = now - timedelta(days=7)
            period = "week"
        elif filter_type == FilterType.MONTH:
            # Compare this month with previous month
            current_start = now - timedelta(days=29)
            current_end = now
            previous_start = now - timedelta(days=59)
            previous_end = now - timedelta(days=30)
            period = "month"
        else:
            # Default to week comparison for other filter types
            current_start = now - timedelta(days=6)
            current_end = now
            previous_start = now - timedelta(days=13)
            previous_end = now - timedelta(days=7)
            period = "week"

        # Count incidents for current period
        current_filters = (
            base_filters
            & Q(created__date__gte=current_start)
            & Q(created__date__lte=current_end)
        )
        current_count = DUCortexSOARIncidentFinalModel.objects.filter(
            current_filters
        ).count()

        # Count incidents for previous period
        previous_filters = (
            base_filters
            & Q(created__date__gte=previous_start)
            & Q(created__date__lte=previous_end)
        )
        previous_count = DUCortexSOARIncidentFinalModel.objects.filter(
            previous_filters
        ).count()

        return current_count, previous_count, period

    def _calculate_percentage_change(self, current, previous, period="day"):
        """Calculate percentage change with time period indication"""
        if period == "N/A":
            return "N/A"

        if previous == 0:
            return f"0% from previous {period}"

        change = ((current - previous) / previous) * 100
        change = max(-100, min(100, change))  # Bound between -100% and 100%
        direction = "↑" if change >= 0 else "↓"
        return f"{direction} {abs(round(change, 1))}% from previous {period}"

    def _parse_date(self, date_str):
        """Safe date parsing from string"""
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError:
            raise ValueError("Invalid date format")


class IncidentsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def _get_date_range_for_filter_type(self, filter_type_value):
        """
        Returns start_date and end_date based on FilterType enum value
        """
        now = make_aware(datetime.now())
        today = now.date()

        try:
            filter_type_int = int(filter_type_value)

            if filter_type_int == FilterType.TODAY.value:  # DAILY
                return today, today

            elif filter_type_int == FilterType.WEEK.value:  # WEEKLY
                # Last 7 days
                start_date = today - timedelta(days=7)
                return start_date, today

            elif filter_type_int == FilterType.MONTH.value:  # MONTHLY
                # Current month
                start_date = today - timedelta(days=30)
                # start_date = today.replace(day=1)
                return start_date, today

            elif filter_type_int == FilterType.CUSTOM_RANGE.value:
                # Custom range should be handled by start_date/end_date parameters
                return None, None

            else:
                return None, None

        except (ValueError, AttributeError):
            return None, None

    def get(self, request):
        try:
            # Step 1: Get current tenant
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)

        # Step 2: Check for active SOAR integration
        soar_integrations = tenant.company.integrations.filter(
            integration_type=IntegrationTypes.SOAR_INTEGRATION,
            soar_subtype=SoarSubTypes.CORTEX_SOAR,
            status=True,
        )

        if not soar_integrations.exists():
            return Response(
                {"error": "No active SOAR integration configured for tenant."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Step 3: Get SOAR tenant IDs
        soar_tenants = tenant.company.soar_tenants.all()
        if not soar_tenants:
            return Response({"error": "No SOAR tenants found."}, status=404)

        soar_ids = [t.id for t in soar_tenants]

        # Step 4: Parse query parameters for filters
        id_filter = request.query_params.get("id")
        db_id_filter = request.query_params.get("db_id")
        account_filter = request.query_params.get("account")
        name_filter = request.query_params.get("name")
        description_filter = request.query_params.get("description")
        status_filter = request.query_params.get("status")
        request.query_params.get("severity")
        priority_filter = request.query_params.get("priority")
        phase_filter = request.query_params.get("phase")
        assignee_filter = request.query_params.get("assignee")
        playbook_filter = request.query_params.get("playbook")
        sla_filter = request.query_params.get("sla")
        mitre_tactic_filter = request.query_params.get("mitre_tactic")
        mitre_technique_filter = request.query_params.get("mitre_technique")
        config_item_filter = request.query_params.get("configuration_item")
        filter_type = request.query_params.get("filter", "all")

        # Date filter parameters
        date_filter_type = request.query_params.get(
            "filter_type"
        )  # New parameter for FilterType enum
        start_date_str = request.query_params.get("start_date")
        end_date_str = request.query_params.get("end_date")
        occurred_start_str = request.query_params.get("occurred_start")
        occurred_end_str = request.query_params.get("occurred_end")
        false_positives = (
            request.query_params.get("false_positives", "").lower() == "true"
        )

        date_format = "%Y-%m-%d"  # Expected format for date inputs

        # Step 5: Initialize filters using same logic as DashboardView
        # Base filters for True Positives (Ready incidents with all required fields)
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

        # Base filters for False Positives (Done incidents)
        false_positive_filters = Q(cortex_soar_tenant__in=soar_ids) & Q(
            itsm_sync_status__iexact="Done"
        )

        # Handle false positives parameter
        if false_positives:
            # For false positives only, use false_positive_filters
            filters = false_positive_filters
        else:
            # Include both true positives AND false positives (same as DashboardView)
            filters = true_positive_filters | false_positive_filters

        # Step 6: Apply non-date filters
        if id_filter:
            filters &= Q(id=id_filter)

        if db_id_filter:
            try:
                db_id_value = int(db_id_filter)
                filters &= Q(db_id=db_id_value)
            except ValueError:
                return Response(
                    {"error": "Invalid db_id format. Must be an integer."}, status=400
                )

        if account_filter:
            filters &= Q(account__icontains=account_filter)

        if name_filter:
            filters &= Q(name__icontains=name_filter)

        if description_filter:
            filters &= Q(name__icontains=description_filter)

        if status_filter:
            filters &= Q(status__iexact=status_filter)

        if priority_filter:
            filters &= Q(incident_priority__iexact=priority_filter)

        if phase_filter:
            filters &= Q(incident_phase__iexact=phase_filter)

        if assignee_filter:
            filters &= Q(owner__iexact=assignee_filter)

        if playbook_filter:
            filters &= Q(playbook_id=playbook_filter)

        if sla_filter:
            try:
                sla_value = int(sla_filter)
                filters &= Q(sla=sla_value)
            except ValueError:
                return Response(
                    {"error": "Invalid sla format. Must be an integer."}, status=400
                )

        # Add MITRE and configuration item filters
        if mitre_tactic_filter:
            filters &= Q(mitre_tactic__icontains=mitre_tactic_filter)

        if mitre_technique_filter:
            filters &= Q(mitre_technique__icontains=mitre_technique_filter)

        if config_item_filter:
            filters &= Q(configuration_item__icontains=config_item_filter)

        # Step 7: Apply filter_type only if status_filter and assignee_filter are not provided
        if filter_type != "all" and not (status_filter or assignee_filter):
            if filter_type == "unassigned":
                filters &= Q(owner__isnull=True)
            elif filter_type == "pending":
                filters &= Q(status="Pending")
            elif filter_type == "false-positive":
                filters &= Q(status="False Positive")
            elif filter_type == "closed":
                filters &= Q(status="Closed")
            elif filter_type == "error":
                filters &= Q(status="Error")

        # Step 8: Apply date filters with validation
        try:
            queryset = DUCortexSOARIncidentFinalModel.objects.filter(filters)

            start_date = None
            end_date = None
            occurred_start = None
            occurred_end = None

            # Handle date_filter_type (FilterType enum)
            if date_filter_type:
                (
                    filter_start_date,
                    filter_end_date,
                ) = self._get_date_range_for_filter_type(date_filter_type)

                if filter_start_date is not None and filter_end_date is not None:
                    # Apply the filter type date range to created field
                    queryset = queryset.filter(
                        created__date__gte=filter_start_date,
                        created__date__lte=filter_end_date,
                    )
                elif date_filter_type != str(FilterType.CUSTOM_RANGE.value):
                    return Response(
                        {
                            "error": f"Invalid date_filter_type: {date_filter_type}. Must be 1-9."
                        },
                        status=400,
                    )

            # Handle custom date ranges (only if not using predefined filter type or if using CUSTOM_RANGE)
            if not date_filter_type or date_filter_type == str(
                FilterType.CUSTOM_RANGE.value
            ):
                if start_date_str:
                    try:
                        start_date = make_aware(
                            datetime.strptime(start_date_str, date_format)
                        ).date()
                        queryset = queryset.filter(created__date__gte=start_date)
                    except ValueError:
                        return Response(
                            {"error": "Invalid start_date format. Use YYYY-MM-DD."},
                            status=400,
                        )

                if end_date_str:
                    try:
                        end_date = make_aware(
                            datetime.strptime(end_date_str, date_format)
                        ).date()
                        queryset = queryset.filter(created__date__lte=end_date)
                    except ValueError:
                        return Response(
                            {"error": "Invalid end_date format. Use YYYY-MM-DD."},
                            status=400,
                        )

            # Handle occurred date filters (these work independently of date_filter_type)
            if occurred_start_str:
                try:
                    occurred_start = make_aware(
                        datetime.strptime(occurred_start_str, date_format)
                    ).date()
                    queryset = queryset.filter(occured__date__gte=occurred_start)
                except ValueError:
                    return Response(
                        {"error": "Invalid occurred_start format. Use YYYY-MM-DD."},
                        status=400,
                    )

            if occurred_end_str:
                try:
                    occurred_end = make_aware(
                        datetime.strptime(occurred_end_str, date_format)
                    ).date()
                    queryset = queryset.filter(occured__date__lte=occurred_end)
                except ValueError:
                    return Response(
                        {"error": "Invalid occurred_end format. Use YYYY-MM-DD."},
                        status=400,
                    )

            # Step 9: Validate date ranges
            if start_date and end_date and start_date > end_date:
                return Response(
                    {"error": "start_date cannot be greater than end_date."}, status=400
                )

            if occurred_start and occurred_end and occurred_start > occurred_end:
                return Response(
                    {"error": "occurred_start cannot be greater than occurred_end."},
                    status=400,
                )

            # Step 10: Query incidents with MITRE fields
            queryset = queryset.values(
                "id",
                "db_id",
                "account",
                "name",
                "status",
                # "severity",
                "incident_priority",
                "incident_phase",
                "created",
                "created_at",
                "owner",
                "playbook_id",
                "occured",
                "sla",
                "mitre_tactic",
                "mitre_technique",
                "configuration_item",
            ).order_by("-created")

            # Step 11: Process incidents
            incidents = []
            offense_db_ids = {
                int(part)
                for row in queryset
                if row["name"]
                for part in [row["name"].split()[0]]
                if part.isdigit()
            }

            # 2. Bulk fetch related offenses
            offenses = IBMQradarOffense.objects.filter(db_id__in=offense_db_ids)
            offense_map = {str(o.db_id): o.id for o in offenses}

            for row in queryset:
                name = row.get("name") or ""

                parts = name.split()
                offense_db_id = parts[0] if parts else None
                # Don't skip incidents without names - include all incidents
                if name and parts and parts[0].isdigit():
                    offense_db_id = parts[0]
                    offense_id = (
                        offense_map.get(offense_db_id) if offense_db_id else None
                    )
                else:
                    offense_db_id = None
                    offense_id = None

                # Use isoformat() for consistent datetime formatting
                created_date = row["created"].isoformat() if row["created"] else "N/A"
                created_at_date = (
                    row["created_at"].isoformat() if row.get("created_at") else "N/A"
                )
                occurred_date = row["occured"].isoformat() if row["occured"] else "N/A"

                description = (
                    row["name"].strip().split(" ", 1)[1]
                    if len(row["name"].strip().split(" ", 1)) > 1
                    else row["name"]
                )

                incidents.append(
                    {
                        "id": f"{row['id']}",
                        "db_id": row["db_id"],
                        "account": row["account"],
                        "name": row["name"],
                        "description": description,
                        "status": row["status"],
                        # "severity": row["severity"],
                        "priority": row["incident_priority"],
                        "phase": row["incident_phase"],
                        "created": created_date,
                        "created_at": created_at_date,
                        "assignee": row["owner"],
                        "playbook": row["playbook_id"],
                        "occurred": occurred_date,
                        "sla": row["sla"],
                        "mitre_tactic": row["mitre_tactic"],
                        "mitre_technique": row["mitre_technique"],
                        "configuration_item": row["configuration_item"],
                        "offense_id": offense_id,
                        "offense_db_id": offense_db_id,
                        "offense_link": request.build_absolute_uri(
                            f"/tenant/api/offense-details/{offense_id}/"
                        ),
                    }
                )

            # Step 12: Pagination
            paginator = PageNumberPagination()
            paginator.page_size = PaginationConstants.PAGE_SIZE
            paginated_incidents = paginator.paginate_queryset(incidents, request)

            # Step 13: Return paginated response
            return paginator.get_paginated_response({"incidents": paginated_incidents})

        except Exception as e:
            logger.error("Error in IncidentsView: %s", str(e))
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class IncidentDetailView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request, incident_db_id):
        try:
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)

        soar_integrations = tenant.company.integrations.filter(
            integration_type=IntegrationTypes.SOAR_INTEGRATION,
            soar_subtype=SoarSubTypes.CORTEX_SOAR,
            status=True,
        ).first()
        if not soar_integrations:
            return Response(
                {"error": "No active SOAR integration configured for tenant."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        soar_tenants = tenant.company.soar_tenants.all()
        if not soar_tenants:
            return Response({"error": "No SOAR tenants found."}, status=404)

        soar_ids = [t.id for t in soar_tenants]

        if not soar_ids:
            return Response({"error": "No SOAR tenants found."}, status=404)

        try:
            # Fetch incident using numeric incident_id
            incident = (
                DUCortexSOARIncidentFinalModel.objects.filter(
                    db_id=incident_db_id, cortex_soar_tenant__in=soar_ids
                )
                .values(
                    "id",
                    "db_id",
                    "account",
                    "name",
                    "status",
                    # "severity",
                    "incident_priority",
                    "created",
                    "modified",
                    "owner",
                    "playbook_id",
                    "occured",
                    "sla",
                    "closed",
                    "closing_user_id",
                    "reason",
                    "incident_phase",
                    "qradar_category",
                    "qradar_sub_category",
                    "incident_tta",
                    "tta_calculation",
                    "incident_tta",
                    "incident_ttn",
                    "incident_ttdn",
                    "source_ips",
                    "log_source_type",
                    "list_of_rules_offense",
                    "mitre_tactic",
                    "mitre_technique",
                    "configuration_item",
                )
                .first()
            )

            if not incident:
                return Response(
                    {"error": "Incident not found"}, status=status.HTTP_404_NOT_FOUND
                )

            # Calculate SLA breach information
            sla_breach_info = {
                "tta": {"is_breached": False, "breach_minutes": 0, "sla_minutes": 0},
                "ttn": {"is_breached": False, "breach_minutes": 0, "sla_minutes": 0},
                "ttdn": {"is_breached": False, "breach_minutes": 0, "sla_minutes": 0},
            }

            # Get SLA metrics for the incident's priority level
            if (
                incident["incident_priority"]
                and incident["occured"]
                and incident["incident_tta"]
                and incident["incident_ttn"]
                and incident["incident_ttdn"]
            ):
                # Get SLA configuration
                if tenant.company.is_default_sla:
                    sla_metrics = DefaultSoarSlaMetric.objects.all()
                else:
                    sla_metrics = SoarTenantSlaMetric.objects.filter(
                        soar_tenant__in=soar_tenants, company=tenant.company
                    )

                # Find matching SLA level for the incident's priority
                sla_metric = None
                for metric in sla_metrics:
                    sla_level_label = SlaLevelChoices(metric.sla_level).label
                    if incident["incident_priority"] == sla_level_label:
                        sla_metric = metric
                        break

                if sla_metric:
                    occured = incident["occured"]

                    # Calculate TTA breach
                    if incident["incident_tta"]:
                        tta_delta_minutes = (
                            incident["incident_tta"] - occured
                        ).total_seconds() / 60
                        sla_breach_info["tta"]["sla_minutes"] = sla_metric.tta_minutes
                        sla_breach_info["tta"]["actual_minutes"] = round(
                            tta_delta_minutes
                        )
                        if tta_delta_minutes > sla_metric.tta_minutes:
                            sla_breach_info["tta"]["is_breached"] = True
                            sla_breach_info["tta"]["breach_minutes"] = round(
                                tta_delta_minutes - sla_metric.tta_minutes, 2
                            )

                    # Calculate TTN breach
                    if incident["incident_ttn"]:
                        ttn_delta_minutes = (
                            incident["incident_ttn"] - occured
                        ).total_seconds() / 60
                        sla_breach_info["ttn"]["sla_minutes"] = sla_metric.ttn_minutes
                        sla_breach_info["ttn"]["actual_minutes"] = round(
                            ttn_delta_minutes
                        )
                        if ttn_delta_minutes > sla_metric.ttn_minutes:
                            sla_breach_info["ttn"]["is_breached"] = True
                            sla_breach_info["ttn"]["breach_minutes"] = round(
                                ttn_delta_minutes - sla_metric.ttn_minutes, 2
                            )

                    # Calculate TTDN breach
                    if incident["incident_ttdn"]:
                        ttdn_delta_minutes = (
                            incident["incident_ttdn"] - occured
                        ).total_seconds() / 60
                        sla_breach_info["ttdn"]["sla_minutes"] = sla_metric.ttdn_minutes
                        sla_breach_info["ttdn"]["actual_minutes"] = round(
                            ttdn_delta_minutes
                        )
                        if ttdn_delta_minutes > sla_metric.ttdn_minutes:
                            sla_breach_info["ttdn"]["is_breached"] = True
                            sla_breach_info["ttdn"]["breach_minutes"] = round(
                                ttdn_delta_minutes - sla_metric.ttdn_minutes, 2
                            )

            # Build timeline
            timeline = []
            if incident["created"]:
                timeline.append(
                    {
                        "icon": "add_alert",
                        "title": "Incident created",
                        "time": incident["created"],
                        "description": "System created the incident",
                        "detail": f"Source: {incident['qradar_category'] or 'SIEM Alert'}",
                    }
                )

            if incident["owner"]:
                timeline.append(
                    {
                        "icon": "person",
                        "title": "Assigned",
                        "time": incident["modified"],
                        "description": f"Incident assigned to {incident['owner']}",
                        "detail": "Action: Changed assignee from Unassigned",
                    }
                )

            if incident["status"] == "Closed" and incident["closed"]:
                timeline.append(
                    {
                        "icon": "task_alt",
                        "title": "Incident closed",
                        "time": incident["closed"],
                        "description": f"Closed by {incident['closing_user_id'] or 'System'}",
                        "detail": f"Reason: {incident['reason'] or 'Not specified'}",
                    }
                )

            if incident["incident_tta"]:
                timeline.append(
                    {
                        "icon": "schedule",
                        "title": "Incident acknowledged",
                        "time": incident["incident_tta"],
                        "description": "Time to acknowledge recorded",
                        "detail": f"TTA: {incident['tta_calculation'] or 'Standard calculation'}",
                    }
                )

            # Sort timeline by time (reverse chronological)
            timeline.sort(key=lambda x: x["time"], reverse=True)

            # Process JSON fields
            source_ips = []
            if incident["source_ips"]:
                try:
                    source_ips = (
                        json.loads(incident["source_ips"])
                        if isinstance(incident["source_ips"], str)
                        else incident["source_ips"]
                    )
                except (json.JSONDecodeError, TypeError):
                    source_ips = []

            # Create related items
            related_items = {"alerts": [], "users": [], "assets": []}

            ticket_id = None
            ticket_db_id = None
            ticket = DuITSMFinalTickets.objects.filter(
                soar_id=incident["db_id"], account_name=incident["account"]
            ).first()
            if ticket is None:
                ticket_db_id = None
            else:
                ticket_id = ticket.id
                ticket_db_id = ticket.db_id
            # Format source IPs and log source types
            offense_db_id = None
            offense_id = None
            offense_db_id = incident["name"].split()[0]
            offenses = IBMQradarOffense.objects.filter(db_id=offense_db_id).first()
            if offenses is None:
                offense_db_id = None
            else:
                offense_id = offenses.id
            source_ips_str = ", ".join(source_ips) if source_ips else "Unknown"
            account_name = f"acc_{incident['account']}"
            notes = DUSoarNotes.objects.filter(
                incident_id=incident["id"],
                integration_id=soar_integrations.id,
                account__iexact=account_name,
            ).order_by("-created")
            if not notes.exists():
                result = IntegrationCredentials.objects.filter(
                    integration__integration_type=IntegrationTypes.SOAR_INTEGRATION,
                    integration__soar_subtype=SoarSubTypes.CORTEX_SOAR,
                    credential_type=CredentialTypes.API_KEY,
                    integration__id=soar_integrations.id,
                ).first()
                sync_notes_for_incident(
                    token=result.api_key,
                    ip_address=result.ip_address,
                    port=result.port,
                    integration_id=result.id,
                    incident_id=incident["id"],
                )
                notes = DUSoarNotes.objects.filter(
                    incident_id=incident["id"],
                    integration_id=soar_integrations.id,
                    account__iexact=account_name,
                ).order_by("-created")

            notes_by_user_dict = defaultdict(list)
            for note in notes:
                user = note.user or "DBot"
                notes_by_user_dict[user].append(
                    {
                        "id": note.id,
                        "db_id": note.db_id,
                        "category": note.category or "",
                        "content": note.content or "",
                        "created": note.created.strftime("%Y-%m-%d %I:%M %p")
                        if note.created
                        else "",
                    }
                )

            # Convert to list of dicts
            notes_by_user = [
                {"user": user, "notes": notes_list}
                for user, notes_list in notes_by_user_dict.items()
            ]

            # Format response
            response = {
                "incident": {
                    "id": incident["db_id"],
                    "db_id": incident["db_id"],
                    "account": incident["account"],
                    "name": incident["name"],
                    "status": incident["status"],
                    # "created": (
                    #     incident["created"].strftime("%Y-%m-%d %I:%M %p")
                    #     if incident["created"]
                    #     else "Unknown"
                    # ),
                    "modified": (
                        incident["modified"] if incident["modified"] else "Unknown"
                    ),
                    "assignee": (
                        "N/A" if incident["owner"] == " " else incident["owner"]
                    ),
                    "description": incident["name"].strip().split(" ", 1)[1],
                    "customFields": {
                        "phase": incident["incident_phase"] or "Detection",
                        "priority": incident["incident_priority"] or None,
                        # "severity": incident["severity"],
                        "sourceIPs": source_ips_str,
                        "logSourceType": incident["log_source_type"],
                        "category": incident["qradar_category"] or None,
                        "sub_category": incident["qradar_sub_category"] or None,
                        "mitre_tactic": incident["mitre_tactic"],
                        "mitre_technique": incident["mitre_technique"],
                        "configuration_item": incident["configuration_item"],
                    },
                    "timeline": timeline,
                    "relatedItems": related_items,
                    "sla": incident["sla"],
                    "playbook": incident["playbook_id"],
                    "occurred": (
                        incident["occured"] if incident["occured"] else "Unknown"
                    ),
                    "offense_id": offense_id,
                    "offense_db_id": offense_db_id,
                    "ticket_id": ticket_id,
                    "ticket_db_id": ticket_db_id,
                    "tta": incident["incident_tta"],
                    "ttn": incident["incident_ttn"],
                    "ttdn": incident["incident_ttdn"],
                    "sla_breach_info": sla_breach_info,
                    "notes": notes_by_user,
                    "list_of_rules_offense": incident["list_of_rules_offense"],
                    "closing_reason": incident["reason"],
                }
            }

            return Response(response, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error in IncidentDetailView: {str(e)}")
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class OffenseDetailsWithFlowsAndAssetsAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request, offense_id):
        try:
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)

        siem_integrations = tenant.integrations.filter(
            integration_type=IntegrationTypes.SIEM_INTEGRATION,
            siem_subtype=SiemSubTypes.IBM_QRADAR,
            status=True,
        )
        if not siem_integrations.exists():
            return Response(
                {"error": "No active SEIM integration configured for tenant."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            # Step 1: Retrieve collector and tenant IDs from TenantQradarMapping
            tenant = request.user
            mappings = TenantQradarMapping.objects.filter(
                tenant__tenant=tenant
            ).values_list("event_collectors__id", "qradar_tenant__id")

            if not mappings:
                return Response(
                    {"error": "No mappings found for the tenant."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Extract collector IDs and tenant IDs
            collector_ids, tenant_ids = zip(*mappings) if mappings else ([], [])

            # Step 2: Retrieve asset IDs based on collector IDs
            assets = IBMQradarAssests.objects.filter(
                event_collector__id__in=collector_ids
            ).values_list("id", flat=True)

            if not assets:
                return Response(
                    {"error": "No assets found for the given collectors."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Step 3: Retrieve the specific offense
            try:
                offense = (
                    IBMQradarOffense.objects.filter(
                        Q(id=offense_id)
                        & Q(assests__id__in=assets)
                        & Q(qradar_tenant_domain__id__in=tenant_ids)
                    )
                    .values()
                    .first()
                )

                if not offense:
                    return Response(
                        {
                            "error": "Offense not found or not associated with the tenant's assets/tenant domain."
                        },
                        status=status.HTTP_404_NOT_FOUND,
                    )

            except IBMQradarOffense.DoesNotExist:
                return Response(
                    {"error": "Offense not found."}, status=status.HTTP_404_NOT_FOUND
                )

            # Step 4: Retrieve assets associated with the offense
            offense_assets = IBMQradarAssests.objects.filter(
                du_ibm_qradar_offenses__id=offense_id
            ).values("id", "db_id", "name", "description")

            offense.pop("source_address_ids", None)
            offense.pop("qradar_tenant_domain_id", None)
            offense.pop("integration_id", None)
            offense.pop("closing_reason_id", None)
            response_data = {
                "offense": offense,  # full offense fields
                "assets": list(offense_assets),
            }

            return Response(response_data, status=status.HTTP_200_OK)

        except Exception:
            return Response(
                {"error": "Invalid tenant or related data not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class IncidentSummaryView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        """
        Retrieve summary of incident counts by severity for the authenticated tenant.
        Filtered by:
        - SOAR tenant
        - True positive logic (ready incidents with proper fields)
        - optional filter_type (1–4)
        - optional severity (0–6)
        - optional priority (1-4)

        Query Parameters:
            filter_type (int): 1=Today, 2=Week, 3=Month, 4=Year
            severity (int): Severity level between 0 and 6
            priority (int): Priority level (1=P4 Low, 2=P3 Medium, 3=P2 High, 4=P1 Critical)

        Returns:
            {
                "summary": {
                    "Unknown": 0,
                    "Low": 0,
                    "Medium": 0,
                    "High": 0,
                    "Critical": 0,
                    "Major": 0,
                    "Minor": 0
                },
                "priority_summary": {
                    "P1 Critical": 0,
                    "P2 High": 0,
                    "P3 Medium": 0,
                    "P4 Low": 0
                }
            }
        """
        try:
            # Step 1: Validate tenant
            tenant = Tenant.objects.get(tenant=request.user)
            soar_ids = tenant.company.soar_tenants.values_list("id", flat=True)

            if not soar_ids:
                return Response({"error": "No SOAR tenants found."}, status=404)

            # Step 2: Apply true positive logic filters (same as AllIncidentsView)
            filters = Q(cortex_soar_tenant__in=soar_ids)
            filters &= (
                ~Q(owner__isnull=True)
                & ~Q(owner__exact="")
                & Q(incident_tta__isnull=False)
                & Q(incident_ttn__isnull=False)
                & Q(incident_ttdn__isnull=False)
                & Q(itsm_sync_status__isnull=False)
                & Q(itsm_sync_status__iexact="Ready")
            )
            false_positive_filters = Q(cortex_soar_tenant__in=soar_ids) & Q(
                itsm_sync_status__iexact="Done"
            )
            filters = filters | false_positive_filters
            # Handle filter_type (same as AllIncidentsView)
            # filter_type = request.query_params.get("filter_type")
            now = timezone.now()
            start_date = now - timedelta(hours=24)
            filters &= Q(created__gte=start_date, created__lte=now)
            # if filter_type:
            #     try:
            #         filter_enum = FilterType(int(filter_type))
            #         if filter_enum == FilterType.TODAY:
            #             filters &= Q(created__date=now)
            #         elif filter_enum == FilterType.WEEK:
            #             start_date = now - timedelta(days=7)
            #             filters &= Q(created__date__gte=start_date)
            #         elif filter_enum == FilterType.MONTH:
            #             start_date = now - timedelta(days=30)
            #             filters &= Q(created__date__gte=start_date)
            #     except Exception:
            #         return Response(
            #             {
            #                 "error": "Invalid filter_type. Use 1=Today, 2=Week, 3=Month, 4=Year."
            #             },
            #             status=400,
            #         )

            priority = request.query_params.get("priority")
            if priority:
                try:
                    priority_int = int(priority)
                    if priority_int not in [choice.value for choice in SlaLevelChoices]:
                        raise ValueError

                    # Get the priority string from the choices (e.g., "P1 Critical")
                    priority_str = SlaLevelChoices(priority_int).label
                    # Extract the prefix (e.g., "P1" from "P1 Critical")
                    priority_prefix = priority_str.split()[0]

                    filters &= Q(incident_priority__icontains=priority_prefix)
                except (ValueError, KeyError):
                    return Response(
                        {
                            "error": "Invalid priority. Must be 1 (P4 Low), 2 (P3 Medium), 3 (P2 High), or 4 (P1 Critical)."
                        },
                        status=400,
                    )

            # Step 3: Apply filters and calculate summary counts
            incidents_qs = DUCortexSOARIncidentFinalModel.objects.filter(filters)

            # Severity summary (same as original)
            # severity_counts = incidents_qs.values("severity").annotate(
            #     count=Count("severity")
            # )

            # Initialize severity summary with all severity labels set to 0
            # severity_summary = {label: 0 for label in SEVERITY_LABELS.values()}

            # # Update counts for severities present in the data
            # for item in severity_counts:
            #     severity_value = item["severity"]
            #     label = SEVERITY_LABELS.get(
            #         severity_value, f"Unknown ({severity_value})"
            #     )
            #     severity_summary[label] = item["count"]

            # Priority summary (using SlaLevelChoices)
            priority_counts = incidents_qs.values("incident_priority").annotate(
                count=Count("incident_priority")
            )

            # Initialize priority summary with priority labels set to 0
            priority_summary = {choice.label: 0 for choice in SlaLevelChoices}

            # Update counts for priorities present in the data
            for item in priority_counts:
                priority_value = item["incident_priority"]
                if priority_value:
                    # Map priority strings to summary labels
                    for choice in SlaLevelChoices:
                        if choice.name in priority_value:  # e.g., "P1" in "P1 Critical"
                            priority_summary[choice.label] += item["count"]

            # Step 4: Return both summaries
            return Response(
                {"priority_summary": priority_summary},
                status=200,
            )

        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)
        except Exception as e:
            logger.error("Error in IncidentSummaryView: %s", str(e))
            return Response({"error": str(e)}, status=500)


class OffenseDetailsWithFlowsAndAssetsDBIDAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request, offense_id):
        try:
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)

        siem_integrations = tenant.company.integrations.filter(
            integration_type=IntegrationTypes.SIEM_INTEGRATION,
            siem_subtype=SiemSubTypes.IBM_QRADAR,
            status=True,
        )
        if not siem_integrations.exists():
            return Response(
                {"error": "No active SEIM integration configured for tenant."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            # Step 1: Retrieve collector and tenant IDs from TenantQradarMapping
            mappings = TenantQradarMapping.objects.filter(
                company=tenant.company,
            ).values_list("event_collectors__id", "qradar_tenant__id")

            if not mappings:
                return Response(
                    {"error": "No mappings found for the tenant."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Extract collector IDs and tenant IDs
            collector_ids, tenant_ids = zip(*mappings) if mappings else ([], [])

            # Step 2: Retrieve asset IDs based on collector IDs
            assets = IBMQradarAssests.objects.filter(
                event_collector__id__in=collector_ids
            ).values_list("id", flat=True)

            if not assets:
                return Response(
                    {"error": "No assets found for the given collectors."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Step 3: Retrieve the specific offense
            try:
                offense = (
                    IBMQradarOffense.objects.filter(
                        Q(db_id=offense_id)
                        & Q(assests__id__in=assets)
                        & Q(qradar_tenant_domain__id__in=tenant_ids)
                    )
                    .values()
                    .first()
                )

                if not offense:
                    return Response(
                        {
                            "error": "Offense not found or not associated with the tenant's assets/tenant domain."
                        },
                        status=status.HTTP_404_NOT_FOUND,
                    )

            except IBMQradarOffense.DoesNotExist:
                return Response(
                    {"error": "Offense not found."}, status=status.HTTP_404_NOT_FOUND
                )

            # Step 4: Retrieve assets associated with the offense
            offense_assets = IBMQradarAssests.objects.filter(
                du_ibm_qradar_offenses__db_id=offense_id
            ).values("id", "db_id", "name", "description")

            offense.pop("source_address_ids", None)
            offense.pop("qradar_tenant_domain_id", None)
            offense.pop("integration_id", None)
            offense.pop("closing_reason_id", None)
            response_data = {
                "offense": offense,  # full offense fields
                "assets": list(offense_assets),
            }

            return Response(response_data, status=status.HTTP_200_OK)

        except Exception:
            return Response(
                {"error": "Invalid tenant or related data not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class OffenseCategoriesAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        """
        Retrieve offense categories from SOAR incidents filtered by tenant.
        Uses DUCortexSOARIncidentFinalModel.qradar_category field.

        Query Parameters:
            filter_type (int): 1=Today, 2=Week, 3=Month, 4=Year, 5=Quarter,
                              6=Last 6 months, 7=Last 3 weeks, 8=Last month,
                              9=Custom range (requires start_date and end_date)
            start_date (YYYY-MM-DD): Start date for custom range or direct filtering
            end_date (YYYY-MM-DD): End date for custom range or direct filtering
            include_fp (bool): Whether to include false positives. Default: true

        Returns:
            {
                "categories": [
                    {"category": "category_name", "count": count_value},
                    ...
                ]
            }
        """
        try:
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)

        # Check for active SOAR integration
        soar_integrations = tenant.company.integrations.filter(
            integration_type=IntegrationTypes.SOAR_INTEGRATION,
            soar_subtype=SoarSubTypes.CORTEX_SOAR,
            status=True,
        )
        if not soar_integrations.exists():
            return Response(
                {"error": "No active SOAR integration configured for tenant."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # Step 1: Get SOAR tenant IDs
            soar_tenants = tenant.company.soar_tenants.all()
            if not soar_tenants:
                return Response(
                    {"error": "No SOAR tenants found."},
                    status=status.HTTP_404_NOT_FOUND,
                )
            soar_ids = [t.id for t in soar_tenants]

            # Step 2: Build base filters using same logic as DashboardView and IncidentSummaryView
            # Base filters for True Positives (Ready incidents with all required fields)
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

            # Base filters for False Positives (Done incidents)
            false_positive_filters = Q(cortex_soar_tenant__in=soar_ids) & Q(
                itsm_sync_status__iexact="Done"
            )

            # Check include_fp parameter (default to true for backward compatibility)
            include_fp = (
                request.query_params.get("include_fp", "true").lower() == "true"
            )

            if include_fp:
                # Include both True Positives and False Positives
                filters = true_positive_filters | false_positive_filters
            else:
                # Include only True Positives
                filters = true_positive_filters

            # Step 3: Handle date filtering
            filter_type = request.query_params.get("filter_type")
            start_date = request.query_params.get("start_date")
            end_date = request.query_params.get("end_date")
            now = timezone.now()

            if start_date and end_date:
                try:
                    start_date_obj = datetime.strptime(start_date, "%Y-%m-%d").date()
                    end_date_obj = datetime.strptime(end_date, "%Y-%m-%d").date()
                    filters &= Q(created__date__gte=start_date_obj) & Q(
                        created__date__lte=end_date_obj
                    )
                except ValueError:
                    return Response(
                        {"error": "Invalid date format. Use YYYY-MM-DD."}, status=400
                    )
            elif filter_type:
                try:
                    filter_type = FilterType(int(filter_type))
                    if filter_type == FilterType.TODAY:
                        filters &= Q(created__date=now.date())
                    elif filter_type == FilterType.WEEK:
                        start_date = now - timedelta(days=7)
                        filters &= Q(created__date__gte=start_date.date())
                    elif filter_type == FilterType.MONTH:
                        start_date = now - timedelta(days=30)
                        filters &= Q(created__date__gte=start_date.date())
                    elif filter_type == FilterType.CUSTOM_RANGE:
                        start_date_str = request.query_params.get("start_date")
                        end_date_str = request.query_params.get("end_date")
                        if not start_date_str or not end_date_str:
                            return Response(
                                {
                                    "error": "Custom range requires both start_date and end_date."
                                },
                                status=400,
                            )
                        try:
                            start_date_obj = datetime.strptime(
                                start_date_str, "%Y-%m-%d"
                            ).date()
                            end_date_obj = datetime.strptime(
                                end_date_str, "%Y-%m-%d"
                            ).date()
                            filters &= Q(created__date__gte=start_date_obj) & Q(
                                created__date__lte=end_date_obj
                            )
                        except ValueError:
                            return Response(
                                {"error": "Invalid date format. Use YYYY-MM-DD."},
                                status=400,
                            )
                except Exception as e:
                    return Response(
                        {"error": f"Invalid filter_type: {str(e)}"}, status=400
                    )

            # Step 4: Query incidents with qradar_category field and group by category
            category_counts = (
                DUCortexSOARIncidentFinalModel.objects.filter(filters)
                .exclude(qradar_category__isnull=True)
                .exclude(qradar_category__exact="")
                .values("qradar_category")
                .annotate(count=Count("id"))
                .order_by("-count")  # Order by count descending
            )

            # Step 5: Format the response for graphing
            response_data = [
                {"category": item["qradar_category"], "count": item["count"]}
                for item in category_counts
            ]

            if not response_data:
                return Response(
                    {
                        "message": "No offense categories found for the given tenant and filters.",
                        "categories": [],
                    },
                    status=status.HTTP_200_OK,
                )

            return Response({"categories": response_data}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error in OffenseCategoriesAPIView: {str(e)}")
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class TopLogSourcesAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        try:
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)

        siem_integrations = tenant.company.integrations.filter(
            integration_type=IntegrationTypes.SIEM_INTEGRATION,
            siem_subtype=SiemSubTypes.IBM_QRADAR,
            status=True,
        )
        if not siem_integrations.exists():
            return Response(
                {"error": "No active SEIM integration configured for tenant."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            # Step 1: Retrieve collector and tenant IDs from TenantQradarMapping
            mappings = TenantQradarMapping.objects.filter(
                company=tenant.company
            ).values_list("event_collectors__id", "qradar_tenant__id")

            if not mappings:
                return Response(
                    {"error": "No mappings found for the tenant."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Extract collector IDs and tenant IDs
            collector_ids, tenant_ids = zip(*mappings) if mappings else ([], [])

            # Step 2: Retrieve asset IDs based on collector IDs
            assets = IBMQradarAssests.objects.filter(
                event_collector__id__in=collector_ids
            ).values_list("id", flat=True)

            if not assets:
                return Response(
                    {"error": "No assets found for the given collectors."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Step 3: Get top 5 assets by offense count
            top_assets = (
                IBMQradarAssests.objects.filter(
                    id__in=assets,
                    du_ibm_qradar_offenses__qradar_tenant_domain__id__in=tenant_ids,
                )
                .annotate(offense_count=Count("du_ibm_qradar_offenses"))
                .order_by("-offense_count")
                .values("id", "db_id", "name", "description", "offense_count")[:10]
            )

            # Step 4: Format the response
            response_data = [
                {
                    "id": asset["id"],
                    "db_id": asset["db_id"],
                    "name": asset["name"],
                    "description": asset["description"],
                    "offense_count": asset["offense_count"],
                }
                for asset in top_assets
            ]

            if not response_data:
                return Response(
                    {
                        "message": "No assets with associated offenses found for the given tenant.",
                        "log_sources": [],
                    },
                    status=status.HTTP_200_OK,
                )

            return Response({"log_sources": response_data}, status=status.HTTP_200_OK)

        except Exception:
            return Response(
                {"error": "Invalid tenant or related data not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class TotalAssetsByTenantAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        try:
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)

        siem_integrations = tenant.company.integrations.filter(
            integration_type=IntegrationTypes.SIEM_INTEGRATION,
            siem_subtype=SiemSubTypes.IBM_QRADAR,
            status=True,
        )
        if not siem_integrations.exists():
            return Response(
                {"error": "No active SEIM integration configured for tenant."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            # Step 1: Retrieve collector IDs from TenantQradarMapping
            mappings = TenantQradarMapping.objects.filter(
                company=tenant.company
            ).values_list("event_collectors__id", flat=True)

            if not mappings:
                return Response(
                    {"error": "No mappings found for the tenant."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Step 2: Count assets based on collector IDs
            asset_count = IBMQradarAssests.objects.filter(
                event_collector__id__in=mappings
            ).aggregate(totalAssets=Count("id"))

            # Step 3: Format the response
            response_data = {"total_assets": asset_count["totalAssets"] or 0}

            return Response(response_data, status=status.HTTP_200_OK)

        except Exception:
            return Response(
                {"error": "Invalid tenant or related data not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class TotalTicketsByTenantAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        try:
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response(
                {"error": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
            )

        itsm_integrations = tenant.company.integrations.filter(
            integration_type=IntegrationTypes.ITSM_INTEGRATION,
            itsm_subtype=ItsmSubTypes.MANAGE_ENGINE,
            status=True,
        )
        if not itsm_integrations.exists():
            return Response(
                {"error": "No active ITSM integration configured for tenant."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            # Step 1: Retrieve ITSM tenant IDs from Tenant
            itsm_tenant_ids = tenant.company.itsm_tenants.values_list("id", flat=True)

            if not itsm_tenant_ids:
                return Response(
                    {"error": "No ITSM tenants found for the tenant."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Step 2: Count tickets based on ITSM tenant IDs
            ticket_count = DuITSMFinalTickets.objects.filter(
                itsm_tenant__in=itsm_tenant_ids
            ).aggregate(totalTickets=Count("id"))

            # Step 3: Format the response
            response_data = {"totalTickets": ticket_count["totalTickets"] or 0}

            return Response(response_data, status=status.HTTP_200_OK)

        except Exception:
            return Response(
                {"error": "Invalid tenant or related data not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class TenantAssetsEPSAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        try:
            tenant = request.user

            # Step 1: Get collector IDs linked to the tenant
            mappings = TenantQradarMapping.objects.filter(
                tenant__tenant=tenant
            ).values_list("event_collectors__id", flat=True)

            if not mappings:
                return Response(
                    {"error": "No event collectors found for the tenant."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            collector_ids = list(mappings)

            # Step 2: Query assets related to those collectors, including average_eps
            assets = IBMQradarAssests.objects.filter(
                event_collector__id__in=collector_ids
            ).values("name", "average_eps")

            if not assets:
                return Response(
                    {"error": "No assets found for the tenant's event collectors."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Step 3: Prepare response data
            response_data = {
                "assets_eps": [
                    {
                        # "id": asset["id"],
                        # "db_id": asset["db_id"],
                        "name": asset["name"],
                        # "description": asset["description"],
                        "average_eps": asset["average_eps"],
                    }
                    for asset in assets
                ],
            }

            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class EPSGraphAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        from django.db.models.functions import TruncWeek
        from pytz import timezone as pytz_timezone

        try:
            filter_value = int(
                request.query_params.get("filter_type", FilterType.TODAY.value)
            )
            # Validate that only supported filter types are used
            if filter_value not in [
                FilterType.TODAY.value,
                FilterType.WEEK.value,
                FilterType.MONTH.value,
                FilterType.CUSTOM_RANGE.value,
            ]:
                return Response(
                    {
                        "error": "Unsupported filter_type. Only supports TODAY (1), WEEK (2), MONTH (3), and CUSTOM_RANGE (9)."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            filter_enum = FilterType(filter_value)
        except (ValueError, KeyError):
            return Response(
                {"error": "Invalid filter value."}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response(
                {"error": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
            )

        now = timezone.now()

        # Time range & truncation logic
        if filter_enum == FilterType.TODAY:
            dubai_tz = pytz_timezone("Asia/Dubai")
            dubai_now = now.astimezone(dubai_tz)
            dubai_midnight = dubai_now.replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            # Convert back to UTC for filtering the UTC-based DB
            start_time = dubai_midnight.astimezone(pytz_timezone("UTC"))
            time_trunc = TruncHour("created_at")
        elif filter_enum == FilterType.WEEK:
            start_time = now - timedelta(days=6)
            time_trunc = TruncDay("created_at")
        elif filter_enum == FilterType.MONTH:
            # Get start of current month and show 4 weeks (28 days back from now)
            start_time = now - timedelta(days=28)
            time_trunc = TruncWeek("created_at")  # Group by week to get 4 data points
        elif filter_enum == FilterType.CUSTOM_RANGE:
            start_str = request.query_params.get("start_date")
            end_str = request.query_params.get("end_date")
            try:
                start_time = datetime.strptime(start_str, "%Y-%m-%d")
                end_time = datetime.strptime(end_str, "%Y-%m-%d") + timedelta(days=1)
                if start_time > end_time:
                    return Response(
                        {"error": "Start date must be before end date."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            except (ValueError, TypeError):
                return Response(
                    {"error": "Invalid custom date format. Use YYYY-MM-DD."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            time_trunc = TruncDate("created_at")
        else:
            return Response(
                {
                    "error": "Unsupported filter_type. Only supports TODAY (1), WEEK (2), MONTH (3), and CUSTOM_RANGE (9)."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Domain mapping
        qradar_tenant_ids = tenant.company.qradar_mappings.values_list(
            "qradar_tenant__id", flat=True
        )

        # Filtering logic
        filter_kwargs = {"domain_id__in": qradar_tenant_ids}
        if filter_enum == FilterType.CUSTOM_RANGE:
            filter_kwargs["created_at__range"] = (start_time, end_time)
        else:
            filter_kwargs["created_at__gte"] = start_time

        # Query EPS data
        eps_data_raw = (
            IBMQradarEPS.objects.filter(**filter_kwargs)
            .annotate(interval=time_trunc)
            .values("interval")
            .annotate(average_eps=Avg("average_eps"), peak_eps=Max("peak_eps"))
            .order_by("interval")
        )

        # Format EPS data with improved interval formatting
        eps_data = []
        total_peak_eps_count = (
            0  # Total counter for all records exceeding contracted volume
        )

        # Get contracted volume for comparison
        mapping = TenantQradarMapping.objects.filter(company=tenant.company).first()
        contracted_volume = mapping.contracted_volume if mapping else None
        contracted_volume_type = mapping.contracted_volume_type if mapping else None
        contracted_volume_type_display = (
            mapping.get_contracted_volume_type_display() if mapping else None
        )

        for entry in eps_data_raw:
            interval_value = entry["interval"]
            peak_row = (
                IBMQradarEPS.objects.filter(**filter_kwargs)
                .annotate(interval=time_trunc)
                .filter(interval=interval_value, peak_eps=entry["peak_eps"])
                .order_by("created_at")  # get earliest if multiple match
                .first()
            )
            peak_eps_time = (
                peak_row.created_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                if peak_row and peak_row.created_at
                else None
            )

            if filter_enum == FilterType.TODAY:
                interval_str = entry["interval"].strftime("%Y-%m-%dT%H:%M:%SZ")
            elif filter_enum == FilterType.MONTH:
                # Format as "Week 1", "Week 2", etc.
                week_num = len(eps_data) + 1
                interval_str = f"Week {week_num}"
            else:
                interval_str = entry["interval"].strftime("%Y-%m-%d")

            peak_eps_value = float(
                Decimal(entry["peak_eps"]).quantize(
                    Decimal("0.01"), rounding=ROUND_HALF_UP
                )
            )
            average_eps_value = float(
                Decimal(entry["average_eps"]).quantize(
                    Decimal("0.01"), rounding=ROUND_HALF_UP
                )
            )

            # Count how many records in this interval have peak_eps exceeding contracted volume
            interval_peak_count = 0
            if contracted_volume:
                # Query to count all records in this interval where peak_eps > contracted_volume
                interval_peak_count = (
                    IBMQradarEPS.objects.filter(**filter_kwargs)
                    .annotate(interval=time_trunc)
                    .filter(
                        interval=interval_value,
                        peak_eps__gt=contracted_volume,  # Count where peak_eps exceeds contracted volume
                    )
                    .count()
                )
                total_peak_eps_count += interval_peak_count

            eps_data.append(
                {
                    "interval": interval_str,
                    "average_eps": average_eps_value,
                    "peak_eps": peak_eps_value,
                    "peak_eps_time": peak_eps_time,
                    "peak_eps_count": interval_peak_count,  # Count of records exceeding threshold in this interval
                }
            )

        return Response(
            {
                "contracted_volume": contracted_volume,
                "contracted_volume_type": contracted_volume_type,
                "contracted_volume_type_display": contracted_volume_type_display,
                "eps_graph": eps_data,
                "total_peak_eps_count": total_peak_eps_count,  # Total count of all records exceeding contracted volume
            },
            status=status.HTTP_200_OK,
        )


class AlertListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        """
        Retrieve alerts filtered by:
        - Tenant-specific integrations or threat intelligence
        - Optional query parameters: id, db_id, title, status, start_date, end_date,
            published_start_date, published_end_date, created_start_date, created_end_date,
            updated_start_date, updated_end_date

        Query Parameters:
            id (int): Exact match on id
            db_id (str): Exact match on db_id (case-insensitive)
            title (str): Partial match on title (case-insensitive)
            status (str): Exact match on status (case-insensitive)
            start_date (YYYY-MM-DD): Alias for published_start_date, alerts with published_time on or after this date
            end_date (YYYY-MM-DD): Alias for published_end_date, alerts with published_time on or before this date
            published_start_date (YYYY-MM-DD): Alerts with published_time on or after this date
            published_end_date (YYYY-MM-DD): Alerts with published_time on or before this date
            created_start_date (YYYY-MM-DD): Alerts with created_at on or after this date
            created_end_date (YYYY-MM-DD): Alerts with created_at on or before this date
            updated_start_date (YYYY-MM-DD): Alerts with updated_at on or after this date
            updated_end_date (YYYY-MM-DD): Alerts with updated_at on or before this date

        Returns:
            Paginated response with count, next, previous, and results
        """
        try:
            # Step 1: Validate tenant
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response(
                {"error": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
            )

        try:
            # Step 2: Get tenant-specific queryset
            if tenant.company.is_defualt_threat_intel:
                integrations = tenant.company.integrations.all()
                queryset = Alert.objects.filter(integration__in=integrations)
            else:
                ti_entry = ThreatIntelligenceTenant.objects.filter(
                    tenants=tenant
                ).first()
                if not ti_entry:
                    return Response(
                        {
                            "error": "No Threat Intelligence configuration found for this tenant."
                        },
                        status=status.HTTP_404_NOT_FOUND,
                    )
                queryset = ThreatIntelligenceTenantAlerts.objects.filter(
                    threat_intelligence=ti_entry
                )

            # Step 3: Build filters
            filters = Q()

            # ID filter
            id_filter = request.query_params.get("id")
            if id_filter:
                try:
                    id_value = int(id_filter)
                    filters &= Q(id=id_value)
                except ValueError:
                    return Response(
                        {"error": "Invalid id format. Must be an integer."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # DB ID filter
            db_id_filter = request.query_params.get("db_id")
            if db_id_filter:
                if not isinstance(db_id_filter, str) or not db_id_filter.strip():
                    return Response(
                        {"error": "Invalid db_id format. Must be a non-empty string."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                filters &= Q(db_id__iexact=db_id_filter)

            # Title filter
            title_filter = request.query_params.get("title")
            if title_filter:
                filters &= Q(title__icontains=title_filter)

            # Status filter
            status_filter = request.query_params.get("status")
            if status_filter:
                filters &= Q(status__iexact=status_filter)

            # Date filters
            # Published time filters (including start_date and end_date as aliases)
            published_start_date_str = request.query_params.get(
                "published_start_date"
            ) or request.query_params.get("start_date")
            published_end_date_str = request.query_params.get(
                "published_end_date"
            ) or request.query_params.get("end_date")
            published_start_date = None
            published_end_date = None

            if published_start_date_str:
                try:
                    published_start_date = parse_datetime(
                        published_start_date_str
                    ).date()
                    filters &= Q(published_time__date__gte=published_start_date)
                except Exception:
                    return Response(
                        {
                            "error": "Invalid start_date or published_start_date format. Use YYYY-MM-DD."
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if published_end_date_str:
                try:
                    published_end_date = parse_datetime(published_end_date_str).date()
                    filters &= Q(published_time__date__lte=published_end_date)
                except ValueError:
                    return Response(
                        {
                            "error": "Invalid end_date or published_end_date format. Use YYYY-MM-DD."
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if (
                published_start_date
                and published_end_date
                and published_start_date > published_end_date
            ):
                return Response(
                    {
                        "error": "start_date/published_start_date cannot be greater than end_date/published_end_date."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Handle null published_time when date filters are applied
            if published_start_date_str or published_end_date_str:
                filters &= Q(published_time__isnull=False)

            # Created at filters
            created_start_date_str = request.query_params.get("created_start_date")
            created_end_date_str = request.query_params.get("created_end_date")
            created_start_date = None
            created_end_date = None

            if created_start_date_str:
                try:
                    created_start_date = parse_datetime(created_start_date_str).date()
                    filters &= Q(created_at__date__gte=created_start_date)
                except ValueError:
                    return Response(
                        {"error": "Invalid created_start_date format. Use YYYY-MM-DD."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if created_end_date_str:
                try:
                    created_end_date = parse_datetime(created_end_date_str).date()
                    filters &= Q(created_at__date__lte=created_end_date)
                except ValueError:
                    return Response(
                        {"error": "Invalid created_end_date format. Use YYYY-MM-DD."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if (
                created_start_date
                and created_end_date
                and created_start_date > created_end_date
            ):
                return Response(
                    {
                        "error": "created_start_date cannot be greater than created_end_date."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Updated at filters
            updated_start_date_str = request.query_params.get("updated_start_date")
            updated_end_date_str = request.query_params.get("updated_end_date")
            updated_start_date = None
            updated_end_date = None

            if updated_start_date_str:
                try:
                    updated_start_date = parse_datetime(updated_start_date_str).date()
                    filters &= Q(updated_at__date__gte=updated_start_date)
                except ValueError:
                    return Response(
                        {"error": "Invalid updated_start_date format. Use YYYY-MM-DD."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if updated_end_date_str:
                try:
                    updated_end_date = parse_datetime(updated_end_date_str).date()
                    filters &= Q(updated_at__date__lte=updated_end_date)
                except ValueError:
                    return Response(
                        {"error": "Invalid updated_end_date format. Use YYYY-MM-DD."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if (
                updated_start_date
                and updated_end_date
                and updated_start_date > updated_end_date
            ):
                return Response(
                    {
                        "error": "updated_start_date cannot be greater than updated_end_date."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            def datetime_to_unix(dt):
                return (
                    int(time.mktime(dt.timetuple())) * 1000
                )  # Convert to milliseconds

            # Handle date filtering
            filter_type = request.query_params.get("filter_type")
            start_date = request.query_params.get("start_date")
            end_date = request.query_params.get("end_date")
            db_timezone = timezone.get_fixed_timezone(240)
            now = timezone.now().astimezone(db_timezone)
            filters_on_date = Q()
            if start_date and end_date:
                try:
                    if not isinstance(start_date, str) or not isinstance(end_date, str):
                        return Response(
                            {
                                "error": "start_date and end_date must be strings in YYYY-MM-DD format."
                            },
                            status=400,
                        )

                    start_date = timezone.make_aware(
                        datetime.strptime(start_date, "%Y-%m-%d"), timezone=db_timezone
                    ).replace(hour=0, minute=0, second=0, microsecond=0)

                    end_date = timezone.make_aware(
                        datetime.strptime(end_date, "%Y-%m-%d"), timezone=db_timezone
                    ).replace(hour=23, minute=59, second=59, microsecond=999999)

                    filters_on_date &= Q(published_time__gte=start_date) & Q(
                        published_time__lte=end_date
                    )
                except ValueError:
                    return Response(
                        {"error": "Invalid date format. Use YYYY-MM-DD."}, status=400
                    )

            elif filter_type:
                try:
                    filter_type = FilterType(int(filter_type))
                    if filter_type == FilterType.TODAY:
                        start_date = now.replace(
                            hour=0, minute=0, second=0, microsecond=0
                        )
                        end_date = now.replace(
                            hour=23, minute=59, second=59, microsecond=999999
                        )
                    elif filter_type == FilterType.WEEK:
                        start_date = now - timedelta(days=now.weekday())
                        start_date = start_date.replace(
                            hour=0, minute=0, second=0, microsecond=0
                        )
                        end_date = now.replace(
                            hour=23, minute=59, second=59, microsecond=999999
                        )
                    elif filter_type == FilterType.MONTH:
                        start_date = now.replace(
                            day=1, hour=0, minute=0, second=0, microsecond=0
                        )
                        end_date = now.replace(
                            hour=23, minute=59, second=59, microsecond=999999
                        )

                    filters_on_date &= Q(published_time__gte=start_date) & Q(
                        published_time__lte=end_date
                    )

                except Exception as e:
                    return Response(
                        {"error": f"Invalid filter_type: {str(e)}"}, status=400
                    )

            # Step 4: Apply filters and sort
            queryset = (
                queryset.filter(filters)
                .filter(filters_on_date)
                .order_by("-published_time")
            )

            # Step 5: Pagination
            paginator = PageNumberPagination()
            paginator.page_size = PaginationConstants.PAGE_SIZE
            paginated_qs = paginator.paginate_queryset(queryset, request)

            # Step 6: Serialize and return response
            serializer = AlertSerializer(paginated_qs, many=True)
            return paginator.get_paginated_response(serializer.data)

        except Exception as e:
            logger.error(f"Error in AlertListView: {str(e)}")
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AlertDetailView(APIView):
    authentication_classes = [JWTAuthentication]

    permission_classes = [IsTenant]

    def get(self, request, alert_id):
        user = request.user

        try:
            tenant = Tenant.objects.get(tenant=user)

        except Tenant.DoesNotExist:
            return Response(
                {"error": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
            )

        if tenant.company.is_defualt_threat_intel:
            # Default TI mode (CywareAlertDetails)

            try:
                alert = Alert.objects.get(id=alert_id)

                alert_details = CywareAlertDetails.objects.get(alert=alert)

                serializer = CywareAlertDetailsSerializer(alert_details)

                return Response(serializer.data, status=status.HTTP_200_OK)

            except (Alert.DoesNotExist, CywareAlertDetails.DoesNotExist):
                # Fallback to fetch from Cyware API

                try:
                    integration = Integration.objects.filter(
                        integration_type=IntegrationTypes.THREAT_INTELLIGENCE,
                        threat_intelligence_subtype=ThreatIntelligenceSubTypes.CYWARE,
                    ).first()

                    if not integration:
                        return Response(
                            {"error": "Cyware integration not found."},
                            status=status.HTTP_404_NOT_FOUND,
                        )

                    credentials = IntegrationCredentials.objects.filter(
                        integration=integration
                    ).first()

                    if (
                        not credentials
                        or not credentials.access_key
                        or not credentials.secret_key
                        or not credentials.base_url
                    ):
                        return Response(
                            {"error": "Valid Cyware credentials not found."},
                            status=status.HTTP_404_NOT_FOUND,
                        )

                    with Cyware(
                        base_url=credentials.base_url,
                        access_key=credentials.access_key,
                        secret_key=credentials.secret_key,
                    ) as cyware:
                        data = cyware.get_alert_detail(short_id=alert_id)

                        if not data:
                            return Response(
                                {"error": "Alert not found in Cyware API."},
                                status=status.HTTP_404_NOT_FOUND,
                            )

                        transformed_data = cyware.transform_alert_detail(data=data)

                        cyware.insert_alert_detail(alert_obj=transformed_data)

                        alert = Alert.objects.get(db_id=alert_id)

                        alert_details = CywareAlertDetails.objects.get(alert=alert)

                        serializer = CywareAlertDetailsSerializer(alert_details)

                        return Response(serializer.data, status=status.HTTP_200_OK)

                except Exception as e:
                    return Response(
                        {"error": f"Cyware API Error: {str(e)}"},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    )

        else:
            # Custom TI mode (CywareTenantAlertDetails)

            ti_entry = ThreatIntelligenceTenant.objects.filter(tenants=tenant).first()

            if not ti_entry:
                return Response(
                    {"error": "Threat Intelligence configuration not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            try:
                alert = ThreatIntelligenceTenantAlerts.objects.get(id=alert_id)

                alert_details = CywareTenantAlertDetails.objects.get(
                    alert=alert, threat_intelligence=ti_entry
                )

                serializer = CywareTenantAlertDetailsSerializer(alert_details)

                return Response(serializer.data, status=status.HTTP_200_OK)

            except (
                ThreatIntelligenceTenantAlerts.DoesNotExist,
                CywareTenantAlertDetails.DoesNotExist,
            ):
                try:
                    alert = ThreatIntelligenceTenantAlerts.objects.get(id=alert_id)

                    with Cyware(
                        base_url=ti_entry.base_url,
                        access_key=ti_entry.access_key,
                        secret_key=ti_entry.secret_key,
                    ) as cyware:
                        data = cyware.get_alert_detail(short_id=alert.db_id)

                        if not data:
                            return Response(
                                {"error": "Alert not found in Cyware API."},
                                status=status.HTTP_404_NOT_FOUND,
                            )

                        transformed_data = cyware.transform_alert_detail_for_tenants(
                            data=data, threat_intel_id=ti_entry.id, alert_id=alert_id
                        )

                        cyware.insert_alert_detail_for_tenants(
                            alert_obj=transformed_data
                        )

                        alert_details = CywareTenantAlertDetails.objects.get(
                            alert=alert, threat_intelligence=ti_entry
                        )

                        serializer = CywareTenantAlertDetailsSerializer(alert_details)

                        return Response(serializer.data, status=status.HTTP_200_OK)

                except Exception as e:
                    return Response(
                        {"error": f"Cyware tenant API error: {str(e)}"},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    )


# class RecentIncidentsView(APIView):
#     authentication_classes = [JWTAuthentication]
#     permission_classes = [IsTenant]

#     def get(self, request):
#         """
#         Retrieve the top 10 incident names based on cleaned incident name occurrence frequency.

#         Uses Django ORM to get incident names, then processes them to remove:
#         - Leading numbers and spaces (e.g., "31607 ")
#         - Leading organization codes (e.g., "AEP-XDR ", "ADGM-")

#         Returns only incident names and their occurrence counts.
#         """
#         try:
#             # Step 1: Validate tenant
#             tenant = Tenant.objects.get(tenant=request.user)
#         except Tenant.DoesNotExist:
#             return Response(
#                 {"error": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
#             )

#         try:
#             # Step 2: Check for active SOAR integration
#             soar_integrations = tenant.company.integrations.filter(
#                 integration_type=IntegrationTypes.SOAR_INTEGRATION,
#                 soar_subtype=SoarSubTypes.CORTEX_SOAR,
#                 status=True,
#             )
#             if not soar_integrations.exists():
#                 return Response(
#                     {"error": "No active SOAR integration configured for tenant."},
#                     status=status.HTTP_400_BAD_REQUEST,
#                 )

#             # Step 3: Get SOAR tenant IDs
#             soar_tenants = tenant.company.soar_tenants.all()
#             if not soar_tenants:
#                 return Response(
#                     {"error": "No SOAR tenants found."},
#                     status=status.HTTP_404_NOT_FOUND,
#                 )

#             soar_ids = [t.id for t in soar_tenants]

#             # Step 4: Build True Positive filters (same as DetailedIncidentReport)
#             all_filters = Q(cortex_soar_tenant_id__in=soar_ids) & (
#                 ~Q(owner__isnull=True)
#                 & ~Q(owner__exact="")
#                 & Q(incident_tta__isnull=False)
#                 & Q(incident_ttn__isnull=False)
#                 & Q(incident_ttdn__isnull=False)
#                 & Q(itsm_sync_status__isnull=False)
#                 & Q(itsm_sync_status__iexact="Ready")
#                 & Q(incident_priority__isnull=False)
#                 & ~Q(incident_priority__exact="")
#             )

#             false_positive_filters = Q(itsm_sync_status__iexact="Done")
#             filters = all_filters | false_positive_filters

#             # Step 6: Use ORM to get incident names efficiently with filters
#             incident_names = (
#                 DUCortexSOARIncidentFinalModel.objects.filter(filters)
#                 .filter(name__isnull=False)
#                 .exclude(name__exact="")
#                 .values_list("name", flat=True)
#             )

#             # Step 7: Process names and group similar incidents
#             from common.utils import group_similar_incidents

#             # Use the new grouping function that handles similarity
#             incident_name_counts = group_similar_incidents(list(incident_names))

#             # Step 6: Get top 10 most frequent incident names
#             top_10_incident_names = incident_name_counts.most_common(10)

#             response_data = [
#                 {"id": idx, "incident_name": incident_name, "occurrence_count": count}
#                 for idx, (incident_name, count) in enumerate(
#                     top_10_incident_names, start=1
#                 )
#             ]

#             return Response(response_data, status=status.HTTP_200_OK)

#         except Exception as e:
#             return Response(
#                 {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )


class RecentIncidentsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        """
        Retrieve the top 10 incident names based on cleaned incident name occurrence frequency.

        Uses Django ORM to get incident names, then processes them to remove:
        - Leading numbers and spaces (e.g., "31607 ")
        - Leading organization codes (e.g., "AEP-XDR ", "ADGM-")

        Returns only incident names and their occurrence counts.
        """
        try:
            # Step 1: Validate tenant
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response(
                {"error": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
            )

        try:
            # Step 2: Check for active SOAR integration
            soar_integrations = tenant.company.integrations.filter(
                integration_type=IntegrationTypes.SOAR_INTEGRATION,
                soar_subtype=SoarSubTypes.CORTEX_SOAR,
                status=True,
            )
            if not soar_integrations.exists():
                return Response(
                    {"error": "No active SOAR integration configured for tenant."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Step 3: Get SOAR tenant IDs
            soar_tenants = tenant.company.soar_tenants.all()
            if not soar_tenants:
                return Response(
                    {"error": "No SOAR tenants found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            soar_ids = [t.id for t in soar_tenants]

            # Step 4: Build True Positive filters (same as DetailedIncidentReport)
            all_filters = Q(cortex_soar_tenant_id__in=soar_ids) & (
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

            false_positive_filters = Q(itsm_sync_status__iexact="Done")
            filters = all_filters | false_positive_filters
            # Step 5: Apply date filtering (same logic as DetailedIncidentReport)
            filter_type = request.query_params.get("filter_type", FilterType.WEEK.value)
            if filter_type is not None:
                try:
                    filter_type = int(filter_type)
                except ValueError:
                    return Response({"error": "Invalid filter_type."}, status=400)

            now = timezone.now()
            start_date_str = request.query_params.get("start_date")
            end_date_str = request.query_params.get("end_date")

            try:
                filter_type = FilterType(int(filter_type))
                if filter_type == FilterType.TODAY:
                    start_date = now
                    filters &= Q(created__date__gte=start_date)
                elif filter_type == FilterType.WEEK:
                    start_date = now - timedelta(days=7)
                    filters &= Q(created__date__gte=start_date)
                elif filter_type == FilterType.MONTH:
                    start_date = now - timedelta(days=30)
                    filters &= Q(created__date__gte=start_date)
                elif filter_type == FilterType.CUSTOM_RANGE:
                    start_date_str = request.query_params.get("start_date")
                    end_date_str = request.query_params.get("end_date")
                    if start_date_str and end_date_str:
                        try:
                            start_date = datetime.strptime(
                                start_date_str, "%Y-%m-%d"
                            ).date()
                            end_date = datetime.strptime(
                                end_date_str, "%Y-%m-%d"
                            ).date()
                            filters &= Q(created__date__gte=start_date) & Q(
                                created__date__lte=end_date
                            )
                            if start_date > end_date:
                                return Response(
                                    {
                                        "error": "Start date cannot be greater than end date."
                                    },
                                    status=400,
                                )
                        except ValueError:
                            return Response(
                                {"error": "Invalid date format. Use YYYY-MM-DD."},
                                status=400,
                            )
            except Exception:
                return Response({"error": "Invalid filter_type."}, status=400)

            # Step 6: Use ORM to get incident names efficiently with filters
            incident_names = (
                DUCortexSOARIncidentFinalModel.objects.filter(filters)
                .filter(name__isnull=False)
                .exclude(name__exact="")
                .values_list("name", flat=True)
            )

            # Step 7: Process names and count occurrences
            incident_name_counts = Counter()

            for name in incident_names:
                # Clean the incident name using the same logic as extract_use_case
                cleaned_name = extract_use_case(name)
                if cleaned_name:  # Only count non-empty cleaned names
                    incident_name_counts[cleaned_name] += 1

            # Step 6: Get top 10 most frequent incident names
            top_10_incident_names = incident_name_counts.most_common(10)

            # Step 7: Build simple response with only incident names and counts
            # response_data = [
            #     {"incident_name": incident_name, "occurrence_count": count}
            #     for incident_name, count in top_10_incident_names
            # ]
            response_data = [
                {"id": idx, "incident_name": incident_name, "occurrence_count": count}
                for idx, (incident_name, count) in enumerate(
                    top_10_incident_names, start=1
                )
            ]

            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# class UseCaseIncidentsView(APIView):
#     authentication_classes = [JWTAuthentication]
#     permission_classes = [IsTenant]

#     def get(self, request):
#         """
#         If use_case parameter is not provided:
#         - Retrieve the top 10 incident names based on cleaned incident name occurrence frequency.

#         If use_case parameter is provided (as int, 1-10):
#         - Get the top 10 incident names first
#         - Select the use case based on the provided index (1=first, 2=second, etc.)
#         - Return paginated incidents that belong to that specific use case

#         Query Parameters:
#             use_case (int): Index of the use case (1-10) to filter incidents
#             filter_type (int): Date filter type
#             start_date (str): Start date for custom range (YYYY-MM-DD)
#             end_date (str): End date for custom range (YYYY-MM-DD)
#         """
#         try:
#             # Step 1: Validate tenant
#             tenant = Tenant.objects.get(tenant=request.user)
#         except Tenant.DoesNotExist:
#             return Response(
#                 {"error": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
#             )

#         try:
#             # Step 2: Check for active SOAR integration
#             soar_integrations = tenant.company.integrations.filter(
#                 integration_type=IntegrationTypes.SOAR_INTEGRATION,
#                 soar_subtype=SoarSubTypes.CORTEX_SOAR,
#                 status=True,
#             )
#             if not soar_integrations.exists():
#                 return Response(
#                     {"error": "No active SOAR integration configured for tenant."},
#                     status=status.HTTP_400_BAD_REQUEST,
#                 )

#             # Step 3: Get SOAR tenant IDs
#             soar_tenants = tenant.company.soar_tenants.all()
#             if not soar_tenants:
#                 return Response(
#                     {"error": "No SOAR tenants found."},
#                     status=status.HTTP_404_NOT_FOUND,
#                 )

#             soar_ids = [t.id for t in soar_tenants]

#             # Step 4: Build True Positive filters (same as DetailedIncidentReport)
#             all_filters = Q(cortex_soar_tenant_id__in=soar_ids) & (
#                 ~Q(owner__isnull=True)
#                 & ~Q(owner__exact="")
#                 & Q(incident_tta__isnull=False)
#                 & Q(incident_ttn__isnull=False)
#                 & Q(incident_ttdn__isnull=False)
#                 & Q(itsm_sync_status__isnull=False)
#                 & Q(itsm_sync_status__iexact="Ready")
#                 & Q(incident_priority__isnull=False)
#                 & ~Q(incident_priority__exact="")
#             )

#             false_positive_filters = Q(itsm_sync_status__iexact="Done")
#             filters = all_filters | false_positive_filters
#             # Step 5: Apply date filtering (same logic as DetailedIncidentReport)
#             filter_type = request.query_params.get("filter_type", FilterType.WEEK.value)
#             if filter_type is not None:
#                 try:
#                     filter_type = int(filter_type)
#                 except ValueError:
#                     return Response({"error": "Invalid filter_type."}, status=400)

#             now = timezone.now()
#             start_date_str = request.query_params.get("start_date")
#             end_date_str = request.query_params.get("end_date")

#             try:
#                 filter_type = FilterType(int(filter_type))
#                 if filter_type == FilterType.WEEK:
#                     start_date = now - timedelta(days=7)
#                     filters &= Q(created__date__gte=start_date)
#                 elif filter_type == FilterType.MONTH:
#                     start_date = now - timedelta(days=30)
#                     filters &= Q(created__date__gte=start_date)
#                 elif filter_type == FilterType.CUSTOM_RANGE:
#                     start_date_str = request.query_params.get("start_date")
#                     end_date_str = request.query_params.get("end_date")
#                     if start_date_str and end_date_str:
#                         try:
#                             start_date = datetime.strptime(
#                                 start_date_str, "%Y-%m-%d"
#                             ).date()
#                             end_date = datetime.strptime(
#                                 end_date_str, "%Y-%m-%d"
#                             ).date()
#                             filters &= Q(created__date__gte=start_date) & Q(
#                                 created__date__lte=end_date
#                             )
#                             if start_date > end_date:
#                                 return Response(
#                                     {
#                                         "error": "Start date cannot be greater than end date."
#                                     },
#                                     status=400,
#                                 )
#                         except ValueError:
#                             return Response(
#                                 {"error": "Invalid date format. Use YYYY-MM-DD."},
#                                 status=400,
#                             )
#             except Exception:
#                 return Response({"error": "Invalid filter_type."}, status=400)

#             # Step 6: Use ORM to get incident names efficiently with filters
#             incident_names = (
#                 DUCortexSOARIncidentFinalModel.objects.filter(filters)
#                 .filter(name__isnull=False)
#                 .exclude(name__exact="")
#                 .values_list("name", flat=True)
#             )

#             # Step 7: Process names using the group_similar_incidents function
#             from common.utils import group_similar_incidents

#             # Use the grouping function that handles similarity
#             incident_name_counts = group_similar_incidents(list(incident_names))

#             # Step 8: Get top 10 most frequent incident names
#             top_10_incident_names = incident_name_counts.most_common(10)

#             # Check if use_case parameter is provided
#             use_case_param = request.query_params.get("use_case")
#             if use_case_param is not None:
#                 # Step 9: Validate use_case parameter
#                 try:
#                     use_case_index = int(use_case_param)
#                     if use_case_index < 1 or use_case_index > 10:
#                         return Response(
#                             {"error": "use_case parameter must be between 1 and 10."},
#                             status=status.HTTP_400_BAD_REQUEST,
#                         )
#                 except ValueError:
#                     return Response(
#                         {"error": "use_case parameter must be an integer."},
#                         status=status.HTTP_400_BAD_REQUEST,
#                     )

#                 # Step 10: Check if the requested use case index exists
#                 if use_case_index > len(top_10_incident_names):
#                     return Response(
#                         {
#                             "error": f"Use case index {use_case_index} not found. Only {len(top_10_incident_names)} use cases available."
#                         },
#                         status=status.HTTP_404_NOT_FOUND,
#                     )

#                 # Step 11: Get the selected use case name (convert from 1-based to 0-based index)
#                 selected_use_case_name = top_10_incident_names[use_case_index - 1][0]

#                 # Step 12: Filter incidents by the selected use case
#                 # Get all incidents and filter by cleaned name matching the selected use case
#                 all_incidents = (
#                     DUCortexSOARIncidentFinalModel.objects.filter(filters)
#                     .filter(name__isnull=False)
#                     .exclude(name__exact="")
#                 )

#                 # Filter incidents where the normalized name matches the selected use case
#                 from difflib import SequenceMatcher

#                 from common.utils import normalize_incident_name

#                 filtered_incidents = []
#                 for incident in all_incidents:
#                     if incident.name:
#                         normalized_name = normalize_incident_name(incident.name)
#                         if normalized_name:
#                             # Use similarity matching like in group_similar_incidents
#                             score = SequenceMatcher(
#                                 None,
#                                 normalized_name.lower(),
#                                 selected_use_case_name.lower(),
#                             ).ratio()
#                             if (
#                                 score >= 0.85
#                             ):  # Same threshold as group_similar_incidents
#                                 filtered_incidents.append(incident)

#                 # Step 13: Apply pagination
#                 paginator = PageNumberPagination()
#                 paginator.page_size = PaginationConstants.PAGE_SIZE
#                 paginated_incidents = paginator.paginate_queryset(
#                     filtered_incidents, request
#                 )

#                 # Step 14: Serialize and return paginated results
#                 serializer = DUCortexSOARIncidentSerializer(
#                     paginated_incidents, many=True
#                 )
#                 return paginator.get_paginated_response(
#                     {
#                         "use_case_name": selected_use_case_name,
#                         "incidents": serializer.data,
#                     }
#                 )

#             else:
#                 # Step 9: Return top 10 use cases (original functionality)
#                 response_data = [
#                     {"incident_name": incident_name, "occurrence_count": count}
#                     for incident_name, count in top_10_incident_names
#                 ]
#                 return Response(response_data, status=status.HTTP_200_OK)

#         except Exception as e:
#             return Response(
#                 {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )


class UseCaseIncidentsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        """
        If use_case parameter is not provided:
        - Retrieve the top 10 incident names based on cleaned incident name occurrence frequency.

        If use_case parameter is provided (as int, 1-10):
        - Get the top 10 incident names first
        - Select the use case based on the provided index (1=first, 2=second, etc.)
        - Return paginated incidents that belong to that specific use case

        Query Parameters:
            use_case (int): Index of the use case (1-10) to filter incidents
            filter_type (int): Date filter type
            start_date (str): Start date for custom range (YYYY-MM-DD)
            end_date (str): End date for custom range (YYYY-MM-DD)
        """
        try:
            # Step 1: Validate tenant
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response(
                {"error": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
            )

        try:
            # Step 2: Check for active SOAR integration
            soar_integrations = tenant.company.integrations.filter(
                integration_type=IntegrationTypes.SOAR_INTEGRATION,
                soar_subtype=SoarSubTypes.CORTEX_SOAR,
                status=True,
            )
            if not soar_integrations.exists():
                return Response(
                    {"error": "No active SOAR integration configured for tenant."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Step 3: Get SOAR tenant IDs
            soar_tenants = tenant.company.soar_tenants.all()
            if not soar_tenants:
                return Response(
                    {"error": "No SOAR tenants found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            soar_ids = [t.id for t in soar_tenants]

            # Step 4: Build True Positive filters (same as DetailedIncidentReport)
            all_filters = Q(cortex_soar_tenant_id__in=soar_ids) & (
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

            false_positive_filters = Q(itsm_sync_status__iexact="Done")
            filters = all_filters | false_positive_filters
            # Step 5: Apply date filtering (same logic as DetailedIncidentReport)
            filter_type = request.query_params.get("filter_type", FilterType.WEEK.value)
            if filter_type is not None:
                try:
                    filter_type = int(filter_type)
                except ValueError:
                    return Response({"error": "Invalid filter_type."}, status=400)

            now = timezone.now()
            start_date_str = request.query_params.get("start_date")
            end_date_str = request.query_params.get("end_date")

            try:
                filter_type = FilterType(int(filter_type))
                if filter_type == FilterType.TODAY:
                    start_date = now
                    filters &= Q(created__date__gte=start_date)
                elif filter_type == FilterType.WEEK:
                    start_date = now - timedelta(days=7)
                    filters &= Q(created__date__gte=start_date)
                elif filter_type == FilterType.MONTH:
                    start_date = now - timedelta(days=30)
                    filters &= Q(created__date__gte=start_date)
                elif filter_type == FilterType.CUSTOM_RANGE:
                    start_date_str = request.query_params.get("start_date")
                    end_date_str = request.query_params.get("end_date")
                    if start_date_str and end_date_str:
                        try:
                            start_date = datetime.strptime(
                                start_date_str, "%Y-%m-%d"
                            ).date()
                            end_date = datetime.strptime(
                                end_date_str, "%Y-%m-%d"
                            ).date()
                            filters &= Q(created__date__gte=start_date) & Q(
                                created__date__lte=end_date
                            )
                            if start_date > end_date:
                                return Response(
                                    {
                                        "error": "Start date cannot be greater than end date."
                                    },
                                    status=400,
                                )
                        except ValueError:
                            return Response(
                                {"error": "Invalid date format. Use YYYY-MM-DD."},
                                status=400,
                            )
            except Exception:
                return Response({"error": "Invalid filter_type."}, status=400)

            # Step 6: Use ORM to get incident names efficiently with filters
            incident_names = (
                DUCortexSOARIncidentFinalModel.objects.filter(filters)
                .filter(name__isnull=False)
                .exclude(name__exact="")
                .values_list("name", flat=True)
            )

            # Step 7: Process names and count occurrences
            incident_name_counts = Counter()

            for name in incident_names:
                # Clean the incident name using the same logic as extract_use_case
                cleaned_name = extract_use_case(name)
                if cleaned_name:  # Only count non-empty cleaned names
                    incident_name_counts[cleaned_name] += 1

            # Step 8: Get top 10 most frequent incident names
            top_10_incident_names = incident_name_counts.most_common(10)

            # Check if use_case parameter is provided
            use_case_param = request.query_params.get("use_case")
            if use_case_param is not None:
                # Step 9: Validate use_case parameter
                try:
                    use_case_index = int(use_case_param)
                    if use_case_index < 1 or use_case_index > 10:
                        return Response(
                            {"error": "use_case parameter must be between 1 and 10."},
                            status=status.HTTP_400_BAD_REQUEST,
                        )
                except ValueError:
                    return Response(
                        {"error": "use_case parameter must be an integer."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                # Step 10: Check if the requested use case index exists
                if use_case_index > len(top_10_incident_names):
                    return Response(
                        {
                            "error": f"Use case index {use_case_index} not found. Only {len(top_10_incident_names)} use cases available."
                        },
                        status=status.HTTP_404_NOT_FOUND,
                    )

                # Step 11: Get the selected use case name (convert from 1-based to 0-based index)
                selected_use_case_name = top_10_incident_names[use_case_index - 1][0]

                # Step 12: Filter incidents by the selected use case
                # Get all incidents and filter by cleaned name matching the selected use case
                all_incidents = (
                    DUCortexSOARIncidentFinalModel.objects.filter(filters)
                    .filter(name__isnull=False)
                    .exclude(name__exact="")
                )

                # Filter incidents where the cleaned name matches the selected use case
                filtered_incidents = []
                for incident in all_incidents:
                    if incident.name:
                        cleaned_name = extract_use_case(incident.name)
                        if cleaned_name == selected_use_case_name:
                            filtered_incidents.append(incident)

                # Step 13: Apply pagination
                paginator = PageNumberPagination()
                paginator.page_size = PaginationConstants.PAGE_SIZE
                paginated_incidents = paginator.paginate_queryset(
                    filtered_incidents, request
                )

                # Step 14: Serialize and return paginated results
                serializer = DUCortexSOARIncidentSerializer(
                    paginated_incidents, many=True
                )
                return paginator.get_paginated_response(
                    {
                        "use_case_name": selected_use_case_name,
                        "incidents": serializer.data,
                    }
                )

            else:
                # Step 9: Return top 10 use cases (original functionality)
                response_data = [
                    {"incident_name": incident_name, "occurrence_count": count}
                    for incident_name, count in top_10_incident_names
                ]
                return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AllIncidentsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        """
        Retrieve up to 10 incidents filtered by:
        - SOAR tenant
        - Both True Positives (Ready incidents with proper fields) and False Positives (Done incidents)
        - optional filter_type (1-9) using created column
        - optional incident_priority (P1, P2, P3, P4)
        - optional custom date range (requires start_date and end_date)

        Query Parameters:
            filter_type (int): 1=Today, 2=Week, 3=Month, 4=Year, 5=Quarter,
                              6=Last 6 months, 7=Last 3 weeks, 8=Last month,
                              9=Custom range (requires start_date and end_date)
            priority (int): 1=P4 Low, 2=P3 Medium, 3=P2 High, 4=P1 Critical
            start_date (str): Required for CUSTOM_RANGE (format: YYYY-MM-DD)
            end_date (str): Required for CUSTOM_RANGE (format: YYYY-MM-DD)

        Returns:
            {
                "data": [...],
                "summary": {
                    "P1 Critical": 0,
                    "P2 High": 0,
                    "P3 Medium": 0,
                    "P4 Low": 0
                }
            }
        """
        try:
            # Step 1: Validate tenant
            tenant = Tenant.objects.get(tenant=request.user)
            soar_ids = tenant.company.soar_tenants.values_list("id", flat=True)

            if not soar_ids:
                return Response({"error": "No SOAR tenants found."}, status=404)

            # Step 2: Build True Positive and False Positive filters (same as DashboardView and IncidentsView)
            # Base filters for True Positives (Ready incidents with all required fields)
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

            # Base filters for False Positives (Done incidents)
            false_positive_filters = Q(cortex_soar_tenant__in=soar_ids) & Q(
                itsm_sync_status__iexact="Done"
            )

            # Combine both True Positives and False Positives
            filters = true_positive_filters | false_positive_filters

            now = timezone.now()
            start_date = now - timedelta(hours=24)
            end_date = now
            # Step 3: Handle filter_type using created column
            # filter_type = request.query_params.get("filter_type")
            # if filter_type:
            #     try:
            #         filter_enum = FilterType(int(filter_type))
            #         now = timezone.now()

            #         if filter_enum == FilterType.TODAY:
            #             # start_date = now.replace(
            #             #     hour=0, minute=0, second=0, microsecond=0
            #             # )

            # elif filter_enum == FilterType.WEEK:
            #     start_date = now - timedelta(days=7)
            #     end_date = now
            # elif filter_enum == FilterType.MONTH:
            #     start_date = now - timedelta(days=30)
            #     end_date = now
            # elif filter_enum == FilterType.CUSTOM_RANGE:
            #     start_date_str = request.query_params.get("start_date")
            #     end_date_str = request.query_params.get("end_date")

            #     if not start_date_str or not end_date_str:
            #         return Response(
            #             {
            #                 "error": "Custom range requires both start_date and end_date."
            #             },
            #             status=400,
            #         )

            #     try:
            #         start_date = datetime.strptime(
            #             start_date_str, "%Y-%m-%d"
            #         ).replace(hour=0, minute=0, second=0, microsecond=0)
            #         end_date = datetime.strptime(
            #             end_date_str, "%Y-%m-%d"
            #         ).replace(hour=23, minute=59, second=59, microsecond=999999)

            #         if end_date < start_date:
            #             return Response(
            #                 {"error": "end_date cannot be before start_date."},
            #                 status=400,
            #             )
            #     except ValueError:
            #         return Response(
            #             {"error": "Invalid date format. Use YYYY-MM-DD."},
            #             status=400,
            #         )

            filters &= Q(created__gte=start_date, created__lte=end_date)
            # except Exception:
            #     return Response(
            #         {
            #             "error": "Invalid filter_type. Use 1-9 as per FilterType enum."
            #         },
            #         status=400,
            #     )

            # Step 4: Handle incident_priority filter
            priority = request.query_params.get("priority")
            if priority:
                try:
                    priority_int = int(priority)
                    if priority_int not in [1, 2, 3, 4]:
                        raise ValueError

                    priority_mapping = {
                        4: "P1",  # P1 Critical
                        3: "P2",  # P2 High
                        2: "P3",  # P3 Medium
                        1: "P4",  # P4 Low
                    }
                    priority_string = priority_mapping[priority_int]
                    filters &= Q(incident_priority__icontains=priority_string)
                except ValueError:
                    return Response(
                        {
                            "error": "Invalid priority. Use 1=P4 Low, 2=P3 Medium, 3=P2 High, 4=P1 Critical."
                        },
                        status=400,
                    )

            # Step 5: Apply filters and get queryset
            incidents_qs = DUCortexSOARIncidentFinalModel.objects.filter(filters)

            # Step 6: Prepare summary counts
            # priority_counts = incidents_qs.values("incident_priority").annotate(
            #     count=Count("incident_priority")
            # )

            # summary = {"P1 Critical": 0, "P2 High": 0, "P3 Medium": 0, "P4 Low": 0}

            # for item in priority_counts:
            #     priority_value = item["incident_priority"]
            #     if priority_value:
            #         if "P1" in priority_value:
            #             summary["P1 Critical"] = item["count"]
            #         elif "P2" in priority_value:
            #             summary["P2 High"] = item["count"]
            #         elif "P3" in priority_value:
            #             summary["P3 Medium"] = item["count"]
            #         elif "P4" in priority_value:
            #             summary["P4 Low"] = item["count"]

            # Step 7: Get top 10 incidents
            incidents = incidents_qs.order_by("-created")[:10]

            # Step 8: Serialize and return response
            serializer = RecentIncidentsSerializer(incidents, many=True)
            return Response({"data": serializer.data}, status=200)

        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)
        except Exception as e:
            logger.error("Error in AllIncidentsView: %s", str(e))
            return Response({"error": str(e)}, status=500)


class SLAIncidentsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        try:
            tenant = Tenant.objects.get(tenant=request.user)
            logger.info(f"Authenticated Tenant ID: {tenant.id}")
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)

        try:
            soar_integrations = tenant.company.integrations.filter(
                integration_type=IntegrationTypes.SOAR_INTEGRATION,
                soar_subtype=SoarSubTypes.CORTEX_SOAR,
                status=True,
            )
            if not soar_integrations.exists():
                return Response(
                    {"error": "No active SOAR integration configured for tenant."},
                    status=400,
                )

            soar_tenants = tenant.company.soar_tenants.all()
            if not soar_tenants:
                return Response({"error": "No SOAR tenants found."}, status=404)
            soar_ids = [t.id for t in soar_tenants]

            filters = Q(cortex_soar_tenant_id__in=soar_ids)

            status_filter = request.query_params.get("status_filter")
            if status_filter:
                filters &= Q(status__icontains=status_filter)

            start_date_str = request.query_params.get("start_date")
            end_date_str = request.query_params.get("end_date")
            filter_type = request.query_params.get("filter_type")

            start_date = (
                datetime.strptime(start_date_str, "%Y-%m-%d").date()
                if start_date_str
                else None
            )
            end_date = (
                datetime.strptime(end_date_str, "%Y-%m-%d").date()
                if end_date_str
                else None
            )

            if start_date and end_date and start_date > end_date:
                return Response(
                    {"error": "start_date cannot be after end_date."}, status=400
                )

            if not (start_date or end_date) and filter_type:
                try:
                    filter_type_enum = FilterType(int(filter_type))
                except Exception:
                    return Response({"error": "Invalid filter_type."}, status=400)

                today = datetime.today().date()
                if filter_type_enum == FilterType.TODAY:
                    start_date = end_date = today
                elif filter_type_enum == FilterType.WEEK:
                    start_date = today - timedelta(days=6)
                    end_date = today
                elif filter_type_enum == FilterType.MONTH:
                    start_date = today - timedelta(days=29)
                    end_date = today

            if start_date:
                filters &= Q(created__date__gte=start_date)
            if end_date:
                filters &= Q(created__date__lte=end_date)

            incidents = DUCortexSOARIncidentFinalModel.objects.filter(
                filters,
                incident_tta__isnull=False,
                incident_ttn__isnull=False,
                incident_ttdn__isnull=False,
            )

            # SLA Metrics selection based on is_default_sla
            if tenant.company.is_default_sla:
                logger.info("SLA source: DefaultSoarSlaMetric")
                sla_metrics = DefaultSoarSlaMetric.objects.all()
            else:
                logger.info("SLA source: SoarTenantSlaMetric")
                sla_metrics = SoarTenantSlaMetric.objects.filter(
                    soar_tenant__in=soar_tenants, company=tenant.company
                )

            sla_metrics_dict = {metric.sla_level: metric for metric in sla_metrics}

            priority_map = {
                "P1 Critical": SlaLevelChoices.P1,
                "P2 High": SlaLevelChoices.P2,
                "P3 Medium": SlaLevelChoices.P3,
                "P4 Low": SlaLevelChoices.P4,
            }
            reverse_priority_label = {v: k for k, v in priority_map.items()}

            priority_counts = {level: 0 for level in SlaLevelChoices.values}
            per_priority_sla_met = {level: 0 for level in SlaLevelChoices.values}

            met_sla_count = 0
            breached_sla_count = 0
            total_incident_count = 0

            for incident in incidents:
                sla_level = priority_map.get(incident.incident_priority)
                if not sla_level:
                    continue

                total_incident_count += 1
                priority_counts[sla_level] += 1

                sla_metric = sla_metrics_dict.get(sla_level)
                if not sla_metric:
                    continue

                any_breach = False
                created = incident.created

                if incident.incident_tta:
                    tta_minutes = (incident.incident_tta - created).total_seconds() / 60
                    if tta_minutes > sla_metric.tta_minutes:
                        any_breach = True

                if incident.incident_ttn:
                    ttn_minutes = (incident.incident_ttn - created).total_seconds() / 60
                    if ttn_minutes > sla_metric.ttn_minutes:
                        any_breach = True

                if incident.incident_ttdn:
                    ttdn_minutes = (
                        incident.incident_ttdn - created
                    ).total_seconds() / 60
                    if ttdn_minutes > sla_metric.ttdn_minutes:
                        any_breach = True

                if any_breach:
                    breached_sla_count += 1
                else:
                    met_sla_count += 1
                    per_priority_sla_met[sla_level] += 1

            sla_details = {}
            for level, metric in sla_metrics_dict.items():
                label = reverse_priority_label.get(level, f"Priority {level}")
                key = label.lower().replace(" ", "_")
                sla_details[key] = {
                    "priority_level": level,
                    "priority_label": label,
                    "tta_minutes": metric.tta_minutes,
                    "ttn_minutes": metric.ttn_minutes,
                    "ttdn_minutes": metric.ttdn_minutes,
                }

            incident_counts = []
            for level, count in priority_counts.items():
                label = reverse_priority_label.get(level, f"Priority {level}")
                met_pct = (
                    round((per_priority_sla_met.get(level, 0) / count) * 100, 2)
                    if count
                    else 0.0
                )
                incident_counts.append(
                    {
                        "priority_level": level,
                        "priority_label": label,
                        "incident_count": count,
                        "total_incident_count": total_incident_count,
                        "met_sla_count": per_priority_sla_met.get(level, 0),
                        "breached_sla_count": breached_sla_count,
                        "breached_sla_percentage": round(
                            (breached_sla_count / total_incident_count) * 100, 2
                        )
                        if total_incident_count > 0
                        else 0,
                        "sla_met_percentage": met_pct,
                        "tta_minutes": sla_metrics_dict.get(level).tta_minutes,
                        "ttn_minutes": sla_metrics_dict.get(level).ttn_minutes,
                        "ttdn_minutes": sla_metrics_dict.get(level).ttdn_minutes,
                    }
                )

            # Calculating overall SLA compliance details
            incident_met_percentage = (
                round((met_sla_count / total_incident_count) * 100, 2)
                if total_incident_count > 0
                else 0
            )

            total_breach_incident_percentage = (
                round((breached_sla_count / total_incident_count) * 100, 2)
                if total_incident_count > 0
                else 0
            )

            overall = {
                "total_breached_incidents": breached_sla_count,
                "total_met_target_incidents": met_sla_count,
                "overall_compliance_percentage": incident_met_percentage,
                "incident_met_percentage": incident_met_percentage,
                "total_breach_incident_percentage": total_breach_incident_percentage,
            }

            return Response(
                {
                    "sla_details": sla_details,
                    "incident_counts": incident_counts,
                    "overall_sla_compliance": overall,
                }
            )

        except Exception as e:
            logger.error(f"SLAIncidentsView Error: {str(e)}")
            return Response({"error": str(e)}, status=500)


class SLAComplianceView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        try:
            tenant = Tenant.objects.get(tenant=request.user)
            logger.info(f"SLAComplianceView | Authenticated Tenant ID: {tenant.id}")
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)

        try:
            soar_integrations = tenant.company.integrations.filter(
                integration_type=IntegrationTypes.SOAR_INTEGRATION,
                soar_subtype=SoarSubTypes.CORTEX_SOAR,
                status=True,
            )
            if not soar_integrations.exists():
                return Response(
                    {"error": "No active SOAR integration configured."}, status=400
                )

            soar_tenants = tenant.company.soar_tenants.all()
            if not soar_tenants:
                return Response({"error": "No SOAR tenants found."}, status=404)
            soar_ids = [t.id for t in soar_tenants]

            # Apply the same filters as in SLASeverityMetricsView
            filters = Q(cortex_soar_tenant_id__in=soar_ids)
            filters &= (
                ~Q(owner__isnull=True)
                & ~Q(owner__exact="")
                & Q(incident_tta__isnull=False)
                & Q(incident_ttn__isnull=False)
                & Q(incident_ttdn__isnull=False)
            )

            incidents = DUCortexSOARIncidentFinalModel.objects.filter(filters)

            if tenant.company.is_default_sla:
                sla_metrics = DefaultSoarSlaMetric.objects.all()
            else:
                sla_metrics = SoarTenantSlaMetric.objects.filter(
                    soar_tenant__in=soar_tenants, company=tenant.company
                )

            sla_metrics_dict = {metric.sla_level: metric for metric in sla_metrics}

            priority_map = {
                "P1 Critical": SlaLevelChoices.P1,
                "P2 High": SlaLevelChoices.P2,
                "P3 Medium": SlaLevelChoices.P3,
                "P4 Low": SlaLevelChoices.P4,
            }

            met_sla_count = 0
            breached_sla_count = 0
            total_incident_count = 0

            for incident in incidents:
                sla_level = priority_map.get(incident.incident_priority)
                if not sla_level:
                    continue

                sla_metric = sla_metrics_dict.get(sla_level)
                if not sla_metric:
                    continue

                total_incident_count += 1
                created = incident.created
                any_breach = False

                if incident.incident_tta:
                    tta_minutes = (incident.incident_tta - created).total_seconds() / 60
                    if tta_minutes > sla_metric.tta_minutes:
                        any_breach = True

                if incident.incident_ttn:
                    ttn_minutes = (incident.incident_ttn - created).total_seconds() / 60
                    if ttn_minutes > sla_metric.ttn_minutes:
                        any_breach = True

                if incident.incident_ttdn:
                    ttdn_minutes = (
                        incident.incident_ttdn - created
                    ).total_seconds() / 60
                    if ttdn_minutes > sla_metric.ttdn_minutes:
                        any_breach = True

                if any_breach:
                    breached_sla_count += 1
                else:
                    met_sla_count += 1

            incident_met_percentage = (
                round((met_sla_count / total_incident_count) * 100, 2)
                if total_incident_count > 0
                else 0.0
            )
            total_breach_incident_percentage = (
                round((breached_sla_count / total_incident_count) * 100, 2)
                if total_incident_count > 0
                else 0.0
            )

            return Response(
                {
                    "total_incidents": total_incident_count,
                    "total_breached_incidents": breached_sla_count,
                    "total_met_incidents": met_sla_count,
                    "overall_compliance_percentage": incident_met_percentage,
                    "incident_met_percentage": incident_met_percentage,
                    "breach_percentage": total_breach_incident_percentage,
                    "compliance_status": "fulfilled"
                    if incident_met_percentage >= 80
                    else "breached",
                }
            )

        except Exception as e:
            logger.error(f"SLAComplianceView Error: {str(e)}")
            return Response({"error": str(e)}, status=500)


class SLASeverityIncidentsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        try:
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)

        try:
            soar_tenants = tenant.company.soar_tenants.all()
            if not soar_tenants:
                return Response({"error": "No SOAR tenants found."}, status=404)

            soar_ids = [t.id for t in soar_tenants]

            true_positive_filters = Q(cortex_soar_tenant_id__in=soar_ids) & (
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

            false_positive_filters = Q(cortex_soar_tenant_id__in=soar_ids) & Q(
                itsm_sync_status__iexact="Done"
            )

            base_filters = true_positive_filters | false_positive_filters

            filters = base_filters

            # ✨ Unified date handling to match DashboardView ✨
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
                    return Response(
                        {"error": "Invalid date format. Use YYYY-MM-DD."}, status=400
                    )

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
                except Exception:
                    return Response({"error": "Invalid filter_type."}, status=400)

            incidents = DUCortexSOARIncidentFinalModel.objects.filter(filters)

            # SLA Metric selection remains unchanged
            if tenant.company.is_default_sla:
                sla_metrics = DefaultSoarSlaMetric.objects.all()
            else:
                sla_metrics = SoarTenantSlaMetric.objects.filter(
                    soar_tenant__in=soar_tenants, company=tenant.company
                )
            sla_metrics_dict = {metric.sla_level: metric for metric in sla_metrics}

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

            severity_counts = {
                "p1_critical": {"total_incidents": 0, "completed_incidents": 0},
                "p2_high": {"total_incidents": 0, "completed_incidents": 0},
                "p3_medium": {"total_incidents": 0, "completed_incidents": 0},
                "p4_low": {"total_incidents": 0, "completed_incidents": 0},
            }

            for incident in incidents:
                sla_level = priority_to_sla_map.get(incident.incident_priority)
                if not sla_level:
                    continue

                sla_metric = sla_metrics_dict.get(sla_level)
                if not sla_metric:
                    continue

                label = sla_to_label_map[sla_level]
                created = incident.created
                any_breach = False

                if incident.incident_tta:
                    if (
                        incident.incident_tta - created
                    ).total_seconds() / 60 > sla_metric.tta_minutes:
                        any_breach = True
                if incident.incident_ttn:
                    if (
                        incident.incident_ttn - created
                    ).total_seconds() / 60 > sla_metric.ttn_minutes:
                        any_breach = True
                if incident.incident_ttdn:
                    if (
                        incident.incident_ttdn - created
                    ).total_seconds() / 60 > sla_metric.ttdn_minutes:
                        any_breach = True

                severity_counts[label]["total_incidents"] += 1
                if not any_breach:
                    severity_counts[label]["completed_incidents"] += 1

            return Response(severity_counts)

        except Exception as e:
            logger.error(f"Error in SLASeverityIncidentsView: {str(e)}")
            return Response({"error": str(e)}, status=500)


class SLASeverityMetricsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        try:
            tenant = Tenant.objects.get(tenant=request.user)
            logger.debug("Tenant ID: %s, User ID: %s", tenant.id, request.user.id)
        except Tenant.DoesNotExist:
            return Response(
                {"error": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
            )

        try:
            soar_tenants = tenant.company.soar_tenants.all()
            if not soar_tenants:
                return Response(
                    {"error": "No SOAR tenants found."},
                    status=status.HTTP_404_NOT_FOUND,
                )
            soar_ids = [t.id for t in soar_tenants]

            is_default = tenant.company.is_default_sla
            if is_default:
                sla_metrics = DefaultSoarSlaMetric.objects.all()
            else:
                sla_metrics = SoarTenantSlaMetric.objects.filter(
                    soar_tenant__in=soar_tenants, company=tenant.company
                )

            sla_metrics_dict = {metric.sla_level: metric for metric in sla_metrics}

            # Get date filtering parameters
            filter_type = request.query_params.get("filter_type")
            start_date = request.query_params.get("start_date")
            end_date = request.query_params.get("end_date")

            # Get all relevant incidents in a single query
            filters = Q(cortex_soar_tenant_id__in=soar_ids)
            filters &= (
                ~Q(owner__isnull=True)
                & ~Q(owner__exact="")
                & Q(incident_tta__isnull=False)
                & Q(incident_ttn__isnull=False)
                & Q(incident_ttdn__isnull=False)
                & Q(
                    incident_priority__in=[
                        SlaLevelChoices.P1.label,
                        SlaLevelChoices.P2.label,
                        SlaLevelChoices.P3.label,
                        SlaLevelChoices.P4.label,
                    ]
                )
            )

            # Apply date filtering
            if filter_type or start_date or end_date:
                try:
                    date_filter = self._get_date_filter(
                        filter_type, start_date, end_date
                    )
                    if date_filter:
                        filters &= date_filter
                except ValueError as e:
                    return Response(
                        {"error": str(e)}, status=status.HTTP_400_BAD_REQUEST
                    )

            incidents = DUCortexSOARIncidentFinalModel.objects.filter(
                filters
            ).select_related()

            # Initialize response structure
            response_data = {
                level.label: {
                    "incident_type": level.label,
                    "total_incidents": 0,
                    "tta_successful_incidents": 0,
                    "tta_breached_incidents": 0,
                    "ttn_successful_incidents": 0,
                    "ttn_breached_incidents": 0,
                    "ttdn_successful_incidents": 0,
                    "ttdn_breached_incidents": 0,
                    "tta_sla_minutes": sla_metrics_dict.get(level, {}).tta_minutes
                    if sla_metrics_dict.get(level)
                    else None,
                    "ttn_sla_minutes": sla_metrics_dict.get(level, {}).ttn_minutes
                    if sla_metrics_dict.get(level)
                    else None,
                    "ttdn_sla_minutes": sla_metrics_dict.get(level, {}).ttdn_minutes
                    if sla_metrics_dict.get(level)
                    else None,
                }
                for level in [
                    SlaLevelChoices.P1,
                    SlaLevelChoices.P2,
                    SlaLevelChoices.P3,
                    SlaLevelChoices.P4,
                ]
            }

            # Process all incidents in memory
            for inc in incidents:
                level = None
                # Find matching SLA level
                for slevel in [
                    SlaLevelChoices.P1,
                    SlaLevelChoices.P2,
                    SlaLevelChoices.P3,
                    SlaLevelChoices.P4,
                ]:
                    if inc.incident_priority == slevel.label:
                        level = slevel
                        break

                if not level or level not in sla_metrics_dict:
                    continue

                sla = sla_metrics_dict[level]
                occured = inc.occured
                response_data[level.label]["total_incidents"] += 1

                # Calculate TTA metrics
                tta_delta = (inc.incident_tta - occured).total_seconds() / 60
                if tta_delta <= sla.tta_minutes:
                    response_data[level.label]["tta_successful_incidents"] += 1
                else:
                    response_data[level.label]["tta_breached_incidents"] += 1

                # Calculate TTN metrics
                ttn_delta = (inc.incident_ttn - occured).total_seconds() / 60
                if ttn_delta <= sla.ttn_minutes:
                    response_data[level.label]["ttn_successful_incidents"] += 1
                else:
                    response_data[level.label]["ttn_breached_incidents"] += 1
                # Calculate TTDN metrics
                ttdn_delta = (inc.incident_ttdn - occured).total_seconds() / 60
                if ttdn_delta <= sla.ttdn_minutes:
                    response_data[level.label]["ttdn_successful_incidents"] += 1
                else:
                    response_data[level.label]["ttdn_breached_incidents"] += 1
            # Create the final response structure
            response = {
                "metrics": list(response_data.values()),
                "is_default": is_default,
            }

            return Response(response)

        except Exception as e:
            logger.error(f"Error in SLASeverityMetricsView: {str(e)}")
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _get_date_filter(self, filter_type, start_date, end_date):
        """
        Get date filter based on filter_type or custom date range.

        Args:
            filter_type (str): Filter type (1=TODAY, 2=WEEK, 3=MONTH, 9=CUSTOM_RANGE)
            start_date (str): Start date in YYYY-MM-DD format
            end_date (str): End date in YYYY-MM-DD format

        Returns:
            Q: Django Q object for date filtering
        """
        from datetime import datetime, timedelta

        from django.utils import timezone

        now = timezone.now()
        today = now.date()

        # Handle predefined filter types
        if filter_type:
            try:
                filter_type_int = int(filter_type)

                if filter_type_int == FilterType.TODAY.value:
                    # Today's incidents
                    return Q(created__date=today)

                elif filter_type_int == FilterType.WEEK.value:
                    # Last 7 days
                    start_date_obj = today - timedelta(days=7)
                    return Q(created__date__gte=start_date_obj) & Q(
                        created__date__lte=today
                    )

                elif filter_type_int == FilterType.MONTH.value:
                    # Last 30 days
                    start_date_obj = today - timedelta(days=30)
                    return Q(created__date__gte=start_date_obj) & Q(
                        created__date__lte=today
                    )

                elif filter_type_int == FilterType.CUSTOM_RANGE.value:
                    # Custom range - requires start_date and end_date
                    if not start_date or not end_date:
                        raise ValueError(
                            "Custom range requires both start_date and end_date."
                        )

                    if start_date > end_date:
                        raise ValueError("Start date must be before end date.")

                    try:
                        start_date_obj = datetime.strptime(
                            start_date, "%Y-%m-%d"
                        ).date()
                        end_date_obj = datetime.strptime(end_date, "%Y-%m-%d").date()
                        return Q(created__date__gte=start_date_obj) & Q(
                            created__date__lte=end_date_obj
                        )
                    except ValueError:
                        raise ValueError("Invalid date format. Use YYYY-MM-DD.")

                else:
                    raise ValueError(
                        f"Invalid filter_type: {filter_type}. Must be 1, 2, 3, or 9."
                    )

            except ValueError as e:
                raise ValueError(str(e))

        # Handle direct start_date and end_date parameters (without filter_type)
        if start_date or end_date:
            date_filter = Q()

            if start_date:
                try:
                    start_date_obj = datetime.strptime(start_date, "%Y-%m-%d").date()
                    date_filter &= Q(created__date__gte=start_date_obj)
                except ValueError:
                    raise ValueError("Invalid start_date format. Use YYYY-MM-DD.")

            if end_date:
                try:
                    end_date_obj = datetime.strptime(end_date, "%Y-%m-%d").date()
                    date_filter &= Q(created__date__lte=end_date_obj)
                except ValueError:
                    raise ValueError("Invalid end_date format. Use YYYY-MM-DD.")

            return date_filter

        return None


class SLABreachedIncidentsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        try:
            # Step 1: Get current tenant
            tenant = Tenant.objects.get(tenant=request.user)
            logger.debug("Tenant ID: %s, User ID: %s", tenant.id, request.user.id)
        except Tenant.DoesNotExist:
            return Response(
                {"error": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
            )

        try:
            # Step 2: Get SOAR tenants
            soar_tenants = tenant.company.soar_tenants.all()
            if not soar_tenants:
                return Response(
                    {"error": "No SOAR tenants found."},
                    status=status.HTTP_404_NOT_FOUND,
                )
            soar_ids = [t.id for t in soar_tenants]

            # Step 3: Get SLA metrics configurations
            is_default = tenant.company.is_default_sla
            if is_default:
                sla_metrics = DefaultSoarSlaMetric.objects.all()
            else:
                sla_metrics = SoarTenantSlaMetric.objects.filter(
                    soar_tenant__in=soar_tenants, company=tenant.company
                )

            sla_metrics_dict = {metric.sla_level: metric for metric in sla_metrics}

            # Step 4: Get filter parameters
            sla_type = request.query_params.get("sla_type", "").lower()
            if sla_type not in ["tta", "ttn", "ttdn"]:
                return Response(
                    {
                        "error": "Invalid sla_type parameter. Must be one of: tta, ttn, ttdn"
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Add SLA level filter parameter
            sla_level_filter = request.query_params.get("sla_level")
            valid_sla_levels = []
            if sla_level_filter:
                try:
                    sla_level_value = int(sla_level_filter)
                    # Validate against SlaLevelChoices
                    valid_sla_level = None
                    for level in SlaLevelChoices:
                        if level.value == sla_level_value:
                            valid_sla_level = level
                            break

                    if not valid_sla_level:
                        valid_values = [
                            f"{level.value} ({level.label})"
                            for level in SlaLevelChoices
                        ]
                        return Response(
                            {
                                "error": f"Invalid sla_level. Must be one of: {', '.join(valid_values)}"
                            },
                            status=status.HTTP_400_BAD_REQUEST,
                        )
                    valid_sla_levels = [valid_sla_level]
                except ValueError:
                    return Response(
                        {"error": "Invalid sla_level format. Must be an integer."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            else:
                # If no specific level is requested, include all levels
                valid_sla_levels = list(SlaLevelChoices)

            # Get other filter parameters
            id_filter = request.query_params.get("id")
            db_id_filter = request.query_params.get("db_id")
            account_filter = request.query_params.get("account")
            name_filter = request.query_params.get("name")
            description_filter = request.query_params.get("description")
            status_filter = request.query_params.get("status")
            severity_filter = request.query_params.get("severity")
            priority_filter = request.query_params.get("priority")
            phase_filter = request.query_params.get("phase")
            assignee_filter = request.query_params.get("assignee")
            playbook_filter = request.query_params.get("playbook")
            sla_filter = request.query_params.get("sla")
            mitre_tactic_filter = request.query_params.get("mitre_tactic")
            mitre_technique_filter = request.query_params.get("mitre_technique")
            config_item_filter = request.query_params.get("configuration_item")
            filter_type = request.query_params.get("filter", "all")

            # Get date filtering parameters (new standardized approach)
            date_filter_type = request.query_params.get("filter_type")
            start_date_str = request.query_params.get("start_date")
            end_date_str = request.query_params.get("end_date")

            # Legacy date parameters (keep for backward compatibility)
            occurred_start_str = request.query_params.get("occurred_start")
            occurred_end_str = request.query_params.get("occurred_end")
            show_only = request.query_params.get(
                "show_only", "all"
            )  # 'all', 'breached', 'achieved'

            date_format = "%Y-%m-%d"

            # Step 5: Build base query filters
            filters = Q(cortex_soar_tenant_id__in=soar_ids)
            filters &= (
                ~Q(owner__isnull=True)
                & ~Q(owner__exact="")
                & Q(incident_tta__isnull=False)
                & Q(incident_ttn__isnull=False)
                & Q(incident_ttdn__isnull=False)
            )

            # Step 6: Apply non-date filters (same as original)
            if id_filter:
                filters &= Q(id=id_filter)

            if db_id_filter:
                try:
                    db_id_value = int(db_id_filter)
                    filters &= Q(db_id=db_id_value)
                except ValueError:
                    return Response(
                        {"error": "Invalid db_id format. Must be an integer."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if account_filter:
                filters &= Q(account__icontains=account_filter)

            if name_filter:
                filters &= Q(name__icontains=name_filter)

            if description_filter:
                filters &= Q(name__icontains=description_filter)

            if status_filter:
                filters &= Q(status__iexact=status_filter)

            if severity_filter:
                try:
                    severity_value = int(severity_filter)
                    filters &= Q(severity=severity_value)
                except ValueError:
                    return Response(
                        {"error": "Invalid severity format. Must be an integer."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if priority_filter:
                valid_priorities = [p.label for p in SlaLevelChoices]
                if priority_filter not in valid_priorities:
                    return Response(
                        {
                            "error": f"Invalid priority. Must be one of: {', '.join(valid_priorities)}"
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                filters &= Q(incident_priority=priority_filter)

            if phase_filter:
                filters &= Q(incident_phase__iexact=phase_filter)

            if assignee_filter:
                filters &= Q(owner__iexact=assignee_filter)

            if playbook_filter:
                filters &= Q(playbook_id=playbook_filter)

            if sla_filter:
                try:
                    sla_value = int(sla_filter)
                    filters &= Q(sla=sla_value)
                except ValueError:
                    return Response(
                        {"error": "Invalid sla format. Must be an integer."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if mitre_tactic_filter:
                filters &= Q(mitre_tactic__icontains=mitre_tactic_filter)

            if mitre_technique_filter:
                filters &= Q(mitre_technique__icontains=mitre_technique_filter)

            if config_item_filter:
                filters &= Q(configuration_item__icontains=config_item_filter)

            # Apply filter_type only if status_filter and assignee_filter are not provided
            if filter_type != "all" and not (status_filter or assignee_filter):
                if filter_type == "unassigned":
                    filters &= Q(owner__isnull=True)
                elif filter_type == "pending":
                    filters &= Q(status="Pending")
                elif filter_type == "false-positive":
                    filters &= Q(status="False Positive")
                elif filter_type == "closed":
                    filters &= Q(status="Closed")
                elif filter_type == "error":
                    filters &= Q(status="Error")

            # Step 7: Apply date filters with validation
            # Apply new standardized date filtering (filter_type approach)
            if date_filter_type or start_date_str or end_date_str:
                try:
                    date_filter = self._get_date_filter(
                        date_filter_type, start_date_str, end_date_str
                    )
                    if date_filter:
                        filters &= date_filter
                except ValueError as e:
                    return Response(
                        {"error": str(e)}, status=status.HTTP_400_BAD_REQUEST
                    )

            # Legacy date filtering for occurred dates (keep for backward compatibility)
            occurred_start = None
            occurred_end = None

            if occurred_start_str:
                try:
                    occurred_start = make_aware(
                        datetime.strptime(occurred_start_str, date_format)
                    ).date()
                    filters &= Q(occured__date__gte=occurred_start)
                except ValueError:
                    return Response(
                        {"error": "Invalid occurred_start format. Use YYYY-MM-DD."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if occurred_end_str:
                try:
                    occurred_end = make_aware(
                        datetime.strptime(occurred_end_str, date_format)
                    ).date()
                    filters &= Q(occured__date__lte=occurred_end)
                except ValueError:
                    return Response(
                        {"error": "Invalid occurred_end format. Use YYYY-MM-DD."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Validate occurred date ranges
            if occurred_start and occurred_end and occurred_start > occurred_end:
                return Response(
                    {"error": "occurred_start cannot be greater than occurred_end."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Step 8: Get all relevant incidents
            incidents = DUCortexSOARIncidentFinalModel.objects.filter(
                filters
            ).select_related()

            # Step 9: Process incidents to find breached and achieved ones
            breached_incidents = []
            achieved_incidents = []
            offense_db_ids = {
                int(part)
                for inc in incidents
                if inc.name
                for part in [inc.name.split()[0]]
                if part.isdigit()
            }

            # Bulk fetch related offenses
            offenses = IBMQradarOffense.objects.filter(db_id__in=offense_db_ids)
            offense_map = {str(o.db_id): o.id for o in offenses}

            for inc in incidents:
                # Find matching SLA level
                level = None
                for slevel in valid_sla_levels:  # Only check the requested SLA levels
                    if inc.incident_priority == slevel.label:
                        level = slevel
                        break

                if not level or level not in sla_metrics_dict:
                    continue

                sla = sla_metrics_dict[level]
                occured = inc.occured

                # Calculate metrics for all SLA types
                tta_delta = (inc.incident_tta - occured).total_seconds() / 60
                ttn_delta = (inc.incident_ttn - occured).total_seconds() / 60
                ttdn_delta = (inc.incident_ttdn - occured).total_seconds() / 60

                # Determine if breached for the requested SLA type
                if sla_type == "tta":
                    is_breached = tta_delta > sla.tta_minutes
                    actual_minutes = tta_delta
                    breach_duration = max(0, actual_minutes - sla.tta_minutes)
                elif sla_type == "ttn":
                    is_breached = ttn_delta > sla.ttn_minutes
                    actual_minutes = ttn_delta
                    breach_duration = max(0, actual_minutes - sla.ttn_minutes)
                else:  # ttdn
                    is_breached = ttdn_delta > sla.ttdn_minutes
                    actual_minutes = ttdn_delta
                    breach_duration = max(0, actual_minutes - sla.ttdn_minutes)

                offense_db_id = None
                offense_id = None
                if inc.name:
                    parts = inc.name.split()
                    if parts and parts[0].isdigit():
                        offense_db_id = parts[0]
                        offense_id = offense_map.get(offense_db_id)

                description = (
                    inc.name.strip().split(" ", 1)[1]
                    if len(inc.name.strip().split(" ", 1)) > 1
                    else inc.name
                )

                incident_data = {
                    "id": str(inc.id),
                    "db_id": inc.db_id,
                    "account": inc.account,
                    "name": inc.name,
                    "description": description,
                    "status": inc.status,
                    "severity": inc.severity,
                    "priority": inc.incident_priority,
                    "phase": inc.incident_phase,
                    "assignee": inc.owner,
                    "playbook": inc.playbook_id,
                    "occurred": inc.occured.isoformat() if inc.occured else "N/A",
                    "sla": inc.sla,
                    "offense_id": offense_id,
                    "offense_db_id": offense_db_id,
                    "offense_link": request.build_absolute_uri(
                        f"/tenant/api/offense-details/{offense_id}/"
                    )
                    if offense_id
                    else None,
                    "sla_type": sla_type.upper(),
                    "sla_minutes": getattr(sla, f"{sla_type}_minutes"),
                    "actual_minutes": round(actual_minutes),
                    "breach_duration_minutes": round(breach_duration),
                    "mitre_tactic": inc.mitre_tactic,
                    "mitre_technique": inc.mitre_technique,
                    "configuration_item": inc.configuration_item,
                    "is_breached": is_breached,
                    # Conditional datetime fields based on sla_type
                    "incident_tta": inc.incident_tta.isoformat()
                    if sla_type == "tta" and inc.incident_tta
                    else None,
                    "incident_ttn": inc.incident_ttn.isoformat()
                    if sla_type == "ttn" and inc.incident_ttn
                    else None,
                    "incident_ttdn": inc.incident_ttdn.isoformat()
                    if sla_type == "ttdn" and inc.incident_ttdn
                    else None,
                }

                if is_breached:
                    breached_incidents.append(incident_data)
                else:
                    achieved_incidents.append(incident_data)

            # Step 10: Filter based on show_only parameter
            if show_only == "breached":
                result_incidents = breached_incidents
            elif show_only == "achieved":
                result_incidents = achieved_incidents
            else:
                result_incidents = breached_incidents + achieved_incidents

            # Step 11: Pagination
            paginator = PageNumberPagination()
            paginator.page_size = PaginationConstants.PAGE_SIZE
            paginated_incidents = paginator.paginate_queryset(result_incidents, request)

            # Step 12: Return response
            return paginator.get_paginated_response(
                {
                    "sla_type": sla_type.upper(),
                    "total_incidents": len(result_incidents),
                    "total_breached": len(breached_incidents),
                    "total_achieved": len(achieved_incidents),
                    "incidents": paginated_incidents,
                }
            )

        except Exception as e:
            logger.error(f"Error in SLAAchievedBreachedIncidentsView: {str(e)}")
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _get_date_filter(self, filter_type, start_date, end_date):
        """
        Get date filter based on filter_type or custom date range.

        Args:
            filter_type (str): Filter type (1=TODAY, 2=WEEK, 3=MONTH, 9=CUSTOM_RANGE)
            start_date (str): Start date in YYYY-MM-DD format
            end_date (str): End date in YYYY-MM-DD format

        Returns:
            Q: Django Q object for date filtering
        """
        from datetime import datetime, timedelta

        from django.utils import timezone

        now = timezone.now()
        today = now.date()

        # Handle predefined filter types
        if filter_type:
            try:
                filter_type_int = int(filter_type)

                if filter_type_int == FilterType.TODAY.value:
                    # Today's incidents
                    return Q(created__date=today)

                elif filter_type_int == FilterType.WEEK.value:
                    # Last 7 days
                    start_date_obj = today - timedelta(days=7)
                    return Q(created__date__gte=start_date_obj) & Q(
                        created__date__lte=today
                    )

                elif filter_type_int == FilterType.MONTH.value:
                    # Last 30 days
                    start_date_obj = today - timedelta(days=30)
                    return Q(created__date__gte=start_date_obj) & Q(
                        created__date__lte=today
                    )

                elif filter_type_int == FilterType.CUSTOM_RANGE.value:
                    # Custom range - requires start_date and end_date
                    if not start_date or not end_date:
                        raise ValueError(
                            "Custom range requires both start_date and end_date."
                        )

                    if start_date > end_date:
                        raise ValueError("Start date must be before end date.")

                    try:
                        start_date_obj = datetime.strptime(
                            start_date, "%Y-%m-%d"
                        ).date()
                        end_date_obj = datetime.strptime(end_date, "%Y-%m-%d").date()
                        return Q(created__date__gte=start_date_obj) & Q(
                            created__date__lte=end_date_obj
                        )
                    except ValueError:
                        raise ValueError("Invalid date format. Use YYYY-MM-DD.")

                else:
                    raise ValueError(
                        f"Invalid filter_type: {filter_type}. Must be 1, 2, 3, or 9."
                    )

            except ValueError as e:
                raise ValueError(str(e))

        # Handle direct start_date and end_date parameters (without filter_type)
        if start_date or end_date:
            date_filter = Q()

            if start_date:
                try:
                    start_date_obj = datetime.strptime(start_date, "%Y-%m-%d").date()
                    date_filter &= Q(created__date__gte=start_date_obj)
                except ValueError:
                    raise ValueError("Invalid start_date format. Use YYYY-MM-DD.")

            if end_date:
                try:
                    end_date_obj = datetime.strptime(end_date, "%Y-%m-%d").date()
                    date_filter &= Q(created__date__lte=end_date_obj)
                except ValueError:
                    raise ValueError("Invalid end_date format. Use YYYY-MM-DD.")

            return date_filter

        return None


class SLAOverviewCardsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        try:
            tenant = Tenant.objects.get(tenant=request.user)
            logger.debug(f"SLAOverviewCardsView | Tenant ID: {tenant.id}")
        except Tenant.DoesNotExist:
            return Response(
                {"error": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
            )

        try:
            # Get SOAR tenants
            soar_tenants = tenant.company.soar_tenants.all()
            if not soar_tenants:
                return Response(
                    {"error": "No SOAR tenants found."},
                    status=status.HTTP_404_NOT_FOUND,
                )
            soar_ids = [t.id for t in soar_tenants]

            # Get SLA metrics
            if tenant.company.is_default_sla:
                sla_metrics = DefaultSoarSlaMetric.objects.all()
            else:
                sla_metrics = SoarTenantSlaMetric.objects.filter(
                    soar_tenant__in=soar_tenants, company=tenant.company
                )
            sla_metrics_dict = {metric.sla_level: metric for metric in sla_metrics}

            # Base filters
            filters = Q(cortex_soar_tenant_id__in=soar_ids)
            # Add true positive filters
            filters &= (
                ~Q(owner__isnull=True)
                & ~Q(owner__exact="")
                & Q(incident_tta__isnull=False)
                & Q(incident_ttn__isnull=False)
                & Q(incident_ttdn__isnull=False)
            )

            # Get all incidents in one query
            incidents = DUCortexSOARIncidentFinalModel.objects.filter(
                filters,
                incident_priority__in=[choice.label for choice in SlaLevelChoices],
            ).select_related()

            # Calculate total incidents across all levels
            total_all_incidents = len(incidents)

            # Initialize results
            results = []

            for level in SlaLevelChoices:
                sla_metric = sla_metrics_dict.get(level)
                if not sla_metric:
                    continue  # Skip if no SLA defined for this level

                level_incidents = [
                    inc for inc in incidents if inc.incident_priority == level.label
                ]
                total_incidents = len(level_incidents)

                if total_incidents == 0:
                    compliance_percent = 0.0
                    breached_percent = 0.0
                    compliance_count = 0
                    breach_count = 0
                    total_percentage = 0.0
                else:
                    compliance_count = 0

                    for inc in level_incidents:
                        occured = inc.occured
                        any_breach = False

                        # Check TTDN
                        ttdn_delta = (inc.incident_ttdn - occured).total_seconds() / 60
                        if ttdn_delta > sla_metric.ttdn_minutes:
                            any_breach = True

                        if not any_breach:
                            compliance_count += 1

                    breach_count = total_incidents - compliance_count
                    compliance_percent = round(
                        (compliance_count / total_incidents) * 100, 2
                    )
                    breached_percent = round(100 - compliance_percent, 2)
                    total_percentage = (
                        round((total_incidents / total_all_incidents) * 100, 2)
                        if total_all_incidents > 0
                        else 0.0
                    )

                results.append(
                    {
                        "priority_level": level.label,
                        "priority_value": level.value,
                        "total_incidents": total_incidents,
                        "total_percentage": total_percentage,
                        "compliance_count": compliance_count,
                        "breach_count": breach_count,
                        "compliance_percentage": compliance_percent,
                        "breached_percentage": breached_percent,
                        "status": "compliant"
                        if compliance_percent >= 80
                        else "breached",
                        "sla_metrics": {
                            "tta_minutes": sla_metric.tta_minutes,
                            "ttn_minutes": sla_metric.ttn_minutes,
                            "ttdn_minutes": sla_metric.ttdn_minutes,
                        },
                    }
                )

            return Response(results)

        except Exception as e:
            logger.error(f"Error in SLAOverviewCardsView: {str(e)}")
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class IncidentReportView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        try:
            # Validate tenant
            try:
                tenant = Tenant.objects.get(tenant=request.user)
                logger.debug("Tenant ID: %s, User ID: %s", tenant.id, request.user.id)
            except Tenant.DoesNotExist:
                return Response({"error": "Tenant not found."}, status=404)

            # Check for active SOAR integration
            soar_integrations = tenant.company.integrations.filter(
                integration_type=IntegrationTypes.SOAR_INTEGRATION,
                soar_subtype=SoarSubTypes.CORTEX_SOAR,
                status=True,
            )
            if not soar_integrations.exists():
                return Response(
                    {"error": "No active SOAR integration configured for tenant."},
                    status=400,
                )

            # Get SOAR tenant IDs
            soar_tenants = tenant.company.soar_tenants.all()
            if not soar_tenants:
                return Response({"error": "No SOAR tenants found."}, status=404)
            soar_ids = [t.id for t in soar_tenants]

            # Get filter_type from query params
            filter_type = request.query_params.get("filter_type")
            if filter_type is not None:
                try:
                    filter_type = int(filter_type)
                except ValueError:
                    return Response({"error": "Invalid filter_type."}, status=400)

            priority_filter = request.query_params.get(
                "incident_priority"
            )  # Optional priority filter

            # Apply date filters based on FilterType Enum
            now = timezone.now()
            date_threshold = None
            comparison_period = None
            period_name = "selected period"

            if filter_type == FilterType.TODAY.value:
                date_threshold = now.replace(hour=0, minute=0, second=0, microsecond=0)
                comparison_period = date_threshold - timedelta(days=1)
                period_name = "today"
            elif filter_type == FilterType.WEEK.value:
                date_threshold = now - timedelta(weeks=1)
                comparison_period = now - timedelta(weeks=2)
                period_name = "last week"
            elif filter_type == FilterType.MONTH.value:
                date_threshold = now - timedelta(days=30)
                comparison_period = now - timedelta(days=60)
                period_name = "last month"
            else:
                # Default to last 3 weeks
                date_threshold = now - timedelta(weeks=3)
                comparison_period = now - timedelta(weeks=6)
                period_name = "last 3 weeks"

            # Build filters for incidents (using created field)
            incident_filters = Q(cortex_soar_tenant_id__in=soar_ids)
            if date_threshold:
                incident_filters &= Q(created__gte=date_threshold)
            if priority_filter:
                try:
                    priority_value = priority_filter
                    incident_filters &= Q(incident_priority=priority_value)
                except ValueError:
                    return Response(
                        {"error": "Invalid incident_priority format."}, status=400
                    )

            # Build filters for logs (using created_at field)
            log_filters = Q(created_at__gte=date_threshold) if date_threshold else Q()

            # Filter incidents
            incidents = DUCortexSOARIncidentFinalModel.objects.filter(
                incident_filters,
                incident_tta__isnull=False,
                incident_ttn__isnull=False,
                incident_ttdn__isnull=False,
            )

            # Fetch SLA metrics based on is_default_sla
            if tenant.company.is_default_sla:
                logger.info("SLA source: DefaultSoarSlaMetric")
                sla_metrics = DefaultSoarSlaMetric.objects.all()
            else:
                logger.info("SLA source: SoarTenantSlaMetric")
                sla_metrics = SoarTenantSlaMetric.objects.filter(
                    soar_tenant__in=soar_tenants, company=tenant.company
                )
            sla_metrics_dict = {metric.sla_level: metric for metric in sla_metrics}

            # Priority mapping
            priority_map = {
                "P1 Critical": SlaLevelChoices.P1,
                "P2 High": SlaLevelChoices.P2,
                "P3 Medium": SlaLevelChoices.P3,
                "P4 Low": SlaLevelChoices.P4,
            }
            reverse_priority_label = {v: k for k, v in priority_map.items()}

            # Group by incident_priority and calculate metrics
            priority_data = incidents.values("incident_priority").annotate(
                total_incidents=Count("id"),
                open_tickets=Count("id", filter=Q(status=1)),
                avg_time_to_notify=Avg(
                    ExpressionWrapper(
                        F("incident_ttn") - F("created"), output_field=DurationField()
                    )
                ),
                avg_time_to_acknowledge=Avg(
                    ExpressionWrapper(
                        F("incident_tta") - F("created"), output_field=DurationField()
                    )
                ),
                avg_time_to_detection=Avg(
                    ExpressionWrapper(
                        F("incident_ttdn") - F("created"), output_field=DurationField()
                    )
                ),
            )

            # Create cards data
            cards_data = []

            # Total incidents card
            total_incidents = DUCortexSOARIncidentFinalModel.objects.filter(
                incident_filters
            ).count()

            # Calculate change percentage for total incidents
            current_filter = Q(
                cortex_soar_tenant_id__in=soar_ids, created__gte=date_threshold
            )
            previous_filter = Q(
                cortex_soar_tenant_id__in=soar_ids,
                created__gte=comparison_period,
                created__lt=date_threshold,
            )

            if priority_filter:
                current_filter &= Q(incident_priority=priority_value)
                previous_filter &= Q(incident_priority=priority_value)

            current_period_count = DUCortexSOARIncidentFinalModel.objects.filter(
                current_filter
            ).count()
            previous_period_count = DUCortexSOARIncidentFinalModel.objects.filter(
                previous_filter
            ).count()

            if previous_period_count > 0:
                change_percent = (
                    (current_period_count - previous_period_count)
                    / previous_period_count
                ) * 100
                change_direction = (
                    "up" if current_period_count >= previous_period_count else "down"
                )
            else:
                change_percent = 0 if current_period_count == 0 else 100
                change_direction = "up" if current_period_count > 0 else "up"
            change_percent = round(change_percent, 2)

            # Get alert count for open tickets
            alert_filter = Q(
                cortex_soar_tenant_id__in=soar_ids,
                status=1,
                created__gte=date_threshold,
            )
            if priority_filter:
                alert_filter &= Q(incident_priority=priority_value)
            alert_count = DUCortexSOARIncidentFinalModel.objects.filter(
                alert_filter
            ).count()

            cards_data.append(
                {
                    "card_type": "total_incidents",
                    "title": f"Total Incidents ({period_name})",
                    "total_incidents": total_incidents,
                    "change_percent": change_percent,
                    "change_direction": change_direction,
                    "alert_count": alert_count,
                    "log_activity": "N/A",
                }
            )

            # Create priority data dictionary
            priority_data_dict = {
                priority_map.get(entry["incident_priority"], 0): {
                    "total_incidents": entry["total_incidents"],
                    "open_tickets": entry["open_tickets"],
                    "avg_time_to_notify": entry["avg_time_to_notify"].total_seconds()
                    / 60
                    if entry["avg_time_to_notify"]
                    else 0,
                    "avg_time_to_acknowledge": entry[
                        "avg_time_to_acknowledge"
                    ].total_seconds()
                    / 60
                    if entry["avg_time_to_acknowledge"]
                    else 0,
                    "avg_time_to_detection": entry[
                        "avg_time_to_detection"
                    ].total_seconds()
                    / 60
                    if entry["avg_time_to_detection"]
                    else 0,
                }
                for entry in priority_data
            }

            # Define all expected priority levels
            priority_levels = [
                (SlaLevelChoices.P1, "Critical"),
                (SlaLevelChoices.P2, "High"),
                (SlaLevelChoices.P3, "Medium"),
                (SlaLevelChoices.P4, "Low"),
            ]

            # Add priority cards
            for priority_value, priority_label in priority_levels:
                priority_metrics = priority_data_dict.get(
                    priority_value,
                    {
                        "total_incidents": 0,
                        "open_tickets": 0,
                        "avg_time_to_notify": 0,
                        "avg_time_to_acknowledge": 0,
                        "avg_time_to_detection": 0,
                    },
                )

                current_priority_filter = Q(
                    cortex_soar_tenant_id__in=soar_ids,
                    created__gte=date_threshold,
                    incident_priority=reverse_priority_label.get(
                        priority_value, "Unknown"
                    ).split(" ")[0],
                )
                if priority_filter:
                    current_priority_filter &= Q(incident_priority=priority_value)
                total_count = DUCortexSOARIncidentFinalModel.objects.filter(
                    current_priority_filter
                ).count()

                previous_priority_filter = Q(
                    cortex_soar_tenant_id__in=soar_ids,
                    created__gte=comparison_period,
                    created__lt=date_threshold,
                    incident_priority=reverse_priority_label.get(
                        priority_value, "Unknown"
                    ).split(" ")[0],
                )
                if priority_filter:
                    previous_priority_filter &= Q(incident_priority=priority_value)
                previous_count = DUCortexSOARIncidentFinalModel.objects.filter(
                    previous_priority_filter
                ).count()

                if previous_count > 0:
                    change_percent_priority = (
                        (total_count - previous_count) / previous_count
                    ) * 100
                    change_direction_priority = (
                        "up" if total_count >= previous_count else "down"
                    )
                else:
                    change_percent_priority = 0 if total_count == 0 else 100
                    change_direction_priority = "up" if total_count > 0 else "up"
                change_percent_priority = round(change_percent_priority, 2)

                cards_data.append(
                    {
                        "card_type": "priority",
                        "title": f"{priority_label}",
                        "priority": priority_label,
                        "total_count": total_count,
                        "change_percent": change_percent_priority,
                        "change_direction": change_direction_priority,
                        "open_tickets": priority_metrics["open_tickets"],
                        "avg_time_to_notify": round(
                            priority_metrics["avg_time_to_notify"], 2
                        ),
                        "avg_time_to_acknowledge": round(
                            priority_metrics["avg_time_to_acknowledge"], 2
                        ),
                        "avg_time_to_detection": round(
                            priority_metrics["avg_time_to_detection"], 2
                        ),
                    }
                )

            # Calculate closed, pending, and assigned incident counts
            closed_incidents = DUCortexSOARIncidentFinalModel.objects.filter(
                status=2,
                created__gte=date_threshold,
                cortex_soar_tenant_id__in=soar_ids,
            ).count()
            pending_incidents = DUCortexSOARIncidentFinalModel.objects.filter(
                status=1,
                created__gte=date_threshold,
                cortex_soar_tenant_id__in=soar_ids,
            ).count()
            assigned_incidents = DUCortexSOARIncidentFinalModel.objects.filter(
                owner__isnull=False,
                created__gte=date_threshold,
                cortex_soar_tenant_id__in=soar_ids,
            ).count()

            incident_status_graph = {
                "closed": closed_incidents,
                "pending": pending_incidents,
                "assigned": assigned_incidents,
            }

            incident_ticket_details = []
            for priority_level in [
                SlaLevelChoices.P4,
                SlaLevelChoices.P3,
                SlaLevelChoices.P2,
                SlaLevelChoices.P1,
            ]:
                sla_metric = sla_metrics_dict.get(priority_level)
                priority_label = (
                    reverse_priority_label.get(priority_level, "Unknown")
                    .replace("P1 ", "")
                    .replace("P2 ", "")
                    .replace("P3 ", "")
                    .replace("P4 ", "")
                )

                if not sla_metric:
                    incident_ticket_details.append(
                        {
                            "priority_label": priority_label,
                            "priority_level": priority_level,
                            "open_tickets": 0,
                            "sla_breach_tickets": 0,
                            "avg_tta_minutes": 0,
                            "avg_ttn_minutes": 0,
                            "avg_ttdn_minutes": 0,
                            "sla_tta_minutes": 0,
                            "sla_ttn_minutes": 0,
                            "sla_ttdn_minutes": 0,
                        }
                    )
                    continue

                # Adjust priority filter to match database incident_priority values
                priority_key = reverse_priority_label.get(priority_level, "Unknown")
                priority_incidents = incidents.filter(incident_priority=priority_key)

                open_tickets = priority_incidents.filter(status=1).count()

                sla_breach_tickets = 0
                tta_times = []
                ttn_times = []
                ttdn_times = []

                for incident in priority_incidents:
                    created = incident.created
                    any_breach = False

                    # Calculate TTA (Time to Acknowledge)
                    if incident.incident_tta and created:
                        tta_delta = (
                            incident.incident_tta - created
                        ).total_seconds() / 60
                        tta_times.append(tta_delta)
                        if tta_delta > sla_metric.tta_minutes:
                            any_breach = True

                    # Calculate TTN (Time to Notify)
                    if incident.incident_ttn and created:
                        ttn_delta = (
                            incident.incident_ttn - created
                        ).total_seconds() / 60
                        ttn_times.append(ttn_delta)
                        if ttn_delta > sla_metric.ttn_minutes:
                            any_breach = True

                    # Calculate TTDN (Time to Detection)
                    if incident.incident_ttdn and created:
                        ttdn_delta = (
                            incident.incident_ttdn - created
                        ).total_seconds() / 60
                        ttdn_times.append(ttdn_delta)
                        if ttdn_delta > sla_metric.ttdn_minutes:
                            any_breach = True

                    if any_breach:
                        sla_breach_tickets += 1

                # Calculate averages, ensuring non-zero results when data exists
                avg_tta = sum(tta_times) / len(tta_times) if tta_times else 0
                avg_ttn = sum(ttn_times) / len(ttn_times) if ttn_times else 0
                avg_ttdn = sum(ttdn_times) / len(ttdn_times) if ttdn_times else 0

                incident_ticket_details.append(
                    {
                        "priority_label": priority_label,
                        "priority_level": priority_level,
                        "open_tickets": open_tickets,
                        "sla_breach_tickets": sla_breach_tickets,
                        "avg_tta_minutes": round(avg_tta, 2) if avg_tta > 0 else 0,
                        "avg_ttn_minutes": round(avg_ttn, 2) if avg_ttn > 0 else 0,
                        "avg_ttdn_minutes": round(avg_ttdn, 2) if avg_ttdn > 0 else 0,
                        "sla_tta_minutes": sla_metric.tta_minutes,
                        "sla_ttn_minutes": sla_metric.ttn_minutes,
                        "sla_ttdn_minutes": sla_metric.ttdn_minutes,
                    }
                )

            # Process incident ticket trend by priority
            incident_ticket_trend_by_priority_graph = []
            if filter_type == FilterType.TODAY.value:
                start_time = date_threshold
                end_time = now
                delta = timedelta(hours=1)
                current_time = start_time
                while current_time <= end_time:
                    next_time = current_time + delta
                    time_filter = Q(created__gte=current_time, created__lt=next_time)
                    counts = (
                        incidents.filter(time_filter)
                        .values("incident_priority")
                        .annotate(count=Count("id"))
                    )
                    priority_counts = {
                        "Critical": 0,
                        "High": 0,
                        "Medium": 0,
                        "Low": 0,
                        "Unknown": 0,
                    }
                    for entry in counts:
                        priority_key = entry["incident_priority"]
                        if priority_key in priority_map:
                            label = (
                                reverse_priority_label[priority_map[priority_key]]
                                .replace("P1 ", "")
                                .replace("P2 ", "")
                                .replace("P3 ", "")
                                .replace("P4 ", "")
                            )
                            priority_counts[label] = entry["count"]
                        else:
                            priority_counts["Unknown"] = entry["count"]
                    incident_ticket_trend_by_priority_graph.append(
                        {"timestamp": current_time.isoformat(), **priority_counts}
                    )
                    current_time = next_time
            elif filter_type in [FilterType.WEEK.value]:
                start_time = date_threshold
                end_time = now
                delta = timedelta(days=1)
                current_time = start_time
                while current_time <= end_time:
                    next_time = current_time + delta
                    time_filter = Q(created__gte=current_time, created__lt=next_time)
                    counts = (
                        incidents.filter(time_filter)
                        .values("incident_priority")
                        .annotate(count=Count("id"))
                    )
                    priority_counts = {
                        "Critical": 0,
                        "High": 0,
                        "Medium": 0,
                        "Low": 0,
                        "Unknown": 0,
                    }
                    for entry in counts:
                        priority_key = entry["incident_priority"]
                        if priority_key in priority_map:
                            label = (
                                reverse_priority_label[priority_map[priority_key]]
                                .replace("P1 ", "")
                                .replace("P2 ", "")
                                .replace("P3 ", "")
                                .replace("P4 ", "")
                            )
                            priority_counts[label] = entry["count"]
                        else:
                            priority_counts["Unknown"] = entry["count"]
                    incident_ticket_trend_by_priority_graph.append(
                        {"timestamp": current_time.isoformat(), **priority_counts}
                    )
                    current_time = next_time
            elif filter_type in [
                FilterType.MONTH.value,
                # FilterType.LAST_MONTH.value,
                # FilterType.QUARTER.value,
                # FilterType.LAST_6_MONTHS.value,
            ]:
                start_time = date_threshold
                end_time = now
                delta = timedelta(weeks=1)
                current_time = start_time
                while current_time <= end_time:
                    next_time = current_time + delta
                    time_filter = Q(created__gte=current_time, created__lt=next_time)
                    counts = (
                        incidents.filter(time_filter)
                        .values("incident_priority")
                        .annotate(count=Count("id"))
                    )
                    priority_counts = {
                        "Critical": 0,
                        "High": 0,
                        "Medium": 0,
                        "Low": 0,
                        "Unknown": 0,
                    }
                    for entry in counts:
                        priority_key = entry["incident_priority"]
                        if priority_key in priority_map:
                            label = (
                                reverse_priority_label[priority_map[priority_key]]
                                .replace("P1 ", "")
                                .replace("P2 ", "")
                                .replace("P3 ", "")
                                .replace("P4 ", "")
                            )
                            priority_counts[label] = entry["count"]
                        else:
                            priority_counts["Unknown"] = entry["count"]
                    incident_ticket_trend_by_priority_graph.append(
                        {"timestamp": current_time.isoformat(), **priority_counts}
                    )
                    current_time = next_time
            else:
                start_time = date_threshold
                end_time = now
                delta = timedelta(days=1)
                current_time = start_time
                while current_time <= end_time:
                    next_time = current_time + delta
                    time_filter = Q(created__gte=current_time, created__lt=next_time)
                    counts = (
                        incidents.filter(time_filter)
                        .values("incident_priority")
                        .annotate(count=Count("id"))
                    )
                    priority_counts = {
                        "Critical": 0,
                        "High": 0,
                        "Medium": 0,
                        "Low": 0,
                        "Unknown": 0,
                    }
                    for entry in counts:
                        priority_key = entry["incident_priority"]
                        if priority_key in priority_map:
                            label = (
                                reverse_priority_label[priority_map[priority_key]]
                                .replace("P1 ", "")
                                .replace("P2 ", "")
                                .replace("P3 ", "")
                                .replace("P4 ", "")
                            )
                            priority_counts[label] = entry["count"]
                        else:
                            priority_counts["Unknown"] = entry["count"]
                    incident_ticket_trend_by_priority_graph.append(
                        {"timestamp": current_time.isoformat(), **priority_counts}
                    )
                    current_time = next_time

            # Service request summary
            created_incidents = DUCortexSOARIncidentFinalModel.objects.filter(
                incident_filters
            ).count()
            open_counts = (
                DUCortexSOARIncidentFinalModel.objects.filter(
                    incident_filters, status=1
                )
                .values("incident_priority")
                .annotate(count=Count("id"))
            )
            closed_counts = (
                DUCortexSOARIncidentFinalModel.objects.filter(
                    incident_filters, status=2
                )
                .values("incident_priority")
                .annotate(count=Count("id"))
            )
            created_counts = (
                DUCortexSOARIncidentFinalModel.objects.filter(incident_filters)
                .values("incident_priority")
                .annotate(count=Count("id"))
            )
            last_30_days_open_counts = (
                DUCortexSOARIncidentFinalModel.objects.filter(
                    Q(
                        cortex_soar_tenant_id__in=soar_ids,
                        status=1,
                        created__gte=now - timedelta(days=30),
                    )
                )
                .values("incident_priority")
                .annotate(count=Count("id"))
            )

            open_priority_counts = {
                "total_count": 0,
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Unknown": 0,
            }
            closed_priority_counts = {
                "total_count": 0,
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Unknown": 0,
            }
            created_priority_counts = {
                "total_count": 0,
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Unknown": 0,
            }
            last_30_days_open_priority_counts = {
                "filter_type": period_name,
                "total_count": 0,
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Unknown": 0,
            }

            for entry in open_counts:
                priority_key = entry["incident_priority"]
                if priority_key in priority_map:
                    label = (
                        reverse_priority_label[priority_map[priority_key]]
                        .replace("P1 ", "")
                        .replace("P2 ", "")
                        .replace("P3 ", "")
                        .replace("P4 ", "")
                    )
                    open_priority_counts[label] = entry["count"]
                else:
                    open_priority_counts["Unknown"] = entry["count"]
                open_priority_counts["total_count"] += entry["count"]

            for entry in closed_counts:
                priority_key = entry["incident_priority"]
                if priority_key in priority_map:
                    label = (
                        reverse_priority_label[priority_map[priority_key]]
                        .replace("P1 ", "")
                        .replace("P2 ", "")
                        .replace("P3 ", "")
                        .replace("P4 ", "")
                    )
                    closed_priority_counts[label] = entry["count"]
                else:
                    closed_priority_counts["Unknown"] = entry["count"]
                closed_priority_counts["total_count"] += entry["count"]

            for entry in created_counts:
                priority_key = entry["incident_priority"]
                if priority_key in priority_map:
                    label = (
                        reverse_priority_label[priority_map[priority_key]]
                        .replace("P1 ", "")
                        .replace("P2 ", "")
                        .replace("P3 ", "")
                        .replace("P4 ", "")
                    )
                    created_priority_counts[label] = entry["count"]
                else:
                    created_priority_counts["Unknown"] = entry["count"]
                created_priority_counts["total_count"] += entry["count"]

            for entry in last_30_days_open_counts:
                priority_key = entry["incident_priority"]
                if priority_key in priority_map:
                    label = (
                        reverse_priority_label[priority_map[priority_key]]
                        .replace("P1 ", "")
                        .replace("P2 ", "")
                        .replace("P3 ", "")
                        .replace("P4 ", "")
                    )
                    last_30_days_open_priority_counts[label] = entry["count"]
                else:
                    last_30_days_open_priority_counts["Unknown"] = entry["count"]
                last_30_days_open_priority_counts["total_count"] += entry["count"]

            service_request_summary = {
                "created_request_count": created_incidents,
                "closed_request_count": closed_incidents,
                "open_requests": open_priority_counts,
                "closed_requests": closed_priority_counts,
                "created_requests": created_priority_counts,
                "last_30_days_open_requests": last_30_days_open_priority_counts,
            }

            # Apply date filters to all log queries
            # TODO : Need to remap these table as per the new tables
            total_eps = (
                TotalEvents.objects.filter(log_filters).aggregate(
                    total_eps=Sum("total_events")
                )["total_eps"]
                or 0
            )
            suspicious_activities = (
                EventCountLog.objects.filter(log_filters)
                .order_by("-event_count")[:10]
                .values("event_name", "event_count")
            )
            recon_event_count = (
                ReconEventLog.objects.filter(log_filters).aggregate(
                    total=Sum("total_recon_events")
                )["total"]
                or 0
            )
            suspicious_event_count = (
                SuspiciousEventLog.objects.filter(log_filters).aggregate(
                    total=Sum("total_suspicious_events")
                )["total"]
                or 0
            )
            dos_event_count = (
                DosEventLog.objects.filter(log_filters).aggregate(
                    total=Sum("total_dos_events")
                )["total"]
                or 0
            )
            top_dos_events = (
                TopDosEventLog.objects.filter(log_filters)
                .order_by("-event_count")[:10]
                .values("event_name", "event_count")
            )

            # TODO : correlated events will be picked from this table  du_ibm_qradar_corelated_events_data
            correlated_event_count = (
                CorrelatedEventLog.objects.filter(log_filters).aggregate(
                    total=Sum("correlated_events_count")
                )["total"]
                or 0
            )

            # TODO : take the count form the table   du_ibm_qradar_corelated_events_data
            daily_event_counts = (
                DailyEventLog.objects.filter(log_filters)
                .order_by("date")
                .values("date", "daily_count")
            )
            # TODO : take the count form the table   du_ibm_qradar_corelated_events_data

            top_alert_events = (
                TopAlertEventLog.objects.filter(log_filters)
                .order_by("-event_count")[:10]
                .values("alert_name", "event_count")
            )
            daily_closure_reasons = (
                DailyClosureReasonLog.objects.filter(log_filters)
                .order_by("date", "closure_reason")
                .values("date", "closure_reason", "reason_count")
            )

            # TODO : take the eps data from the du_ibm_qradar_eps
            monthly_avg_eps = (
                MonthlyAvgEpsLog.objects.filter(log_filters).aggregate(
                    total=Sum("monthly_avg_eps")
                )["total"]
                or 0
            )
            # TODO : take the eps data from the du_ibm_qradar_eps

            last_month_avg_eps = (
                LastMonthAvgEpsLog.objects.filter(log_filters).aggregate(
                    total=Sum("last_month_avg_eps")
                )["total"]
                or 0
            )
            # TODO : take the eps data from the du_ibm_qradar_eps

            weekly_avg_eps = (
                WeeklyAvgEpsLog.objects.filter(log_filters)
                .annotate(created_at_date=TruncDate("created_at"))
                .values("week", "week_start", "created_at_date")
                .annotate(weekly_avg_eps=Avg("weekly_avg_eps"))
                .order_by("week_start")
                .values(
                    "week",
                    "week_start",
                    "weekly_avg_eps",
                    created_at=F("created_at_date"),
                )
            )

            # TODO : table du_ibm_qradar_sensitive_count_wise_data
            total_traffic = (
                TotalTrafficLog.objects.filter(log_filters).aggregate(
                    total=Sum("total_traffic")
                )["total"]
                or 0
            )
            # TODO : Show top 10 destination ips on from the table du_ibm_qradar_sensitive_count_wise_data based on aggregation
            destination_addresses = (
                DestinationAddressLog.objects.filter(log_filters)
                .order_by("-address_count")[:10]
                .values("destination_address", "address_count")
            )
            # TODO : based on the destination ip use the table du_ibm_qradar_sensitive_count_wise_data
            top_destination_connections = (
                TopDestinationConnectionLog.objects.filter(log_filters)
                .order_by("-connection_count")[:5]
                .values("destination_address", "connection_count")
            )
            # TODO : take the count form the table   du_ibm_qradar_corelated_events_data
            daily_event_count = (
                DailyEventCountLog.objects.filter(log_filters)
                .values("full_date")
                .annotate(daily_count=Min("daily_count"))
                .order_by("full_date")
            )

            # Add to your response
            return Response(
                {
                    "cards_data": cards_data,
                    "incident_status_graph": incident_status_graph,
                    "incident_ticket_details": incident_ticket_details,
                    "incident_ticket_trend_by_priority_graph": incident_ticket_trend_by_priority_graph,
                    "service_request_summary": service_request_summary,
                    "total_eps": total_eps,
                    "threat_trending_events": {
                        "suspicious_activities": list(suspicious_activities),
                        "recon_event_count": recon_event_count,
                        "suspicious_event_count": suspicious_event_count,
                        "dos_event_count": dos_event_count,
                        "top_dos_events": list(top_dos_events),
                        "correlated_event_count": correlated_event_count,
                        "daily_event_counts": list(daily_event_counts),
                        "top_alert_events": list(top_alert_events),
                        "daily_closure_reasons": list(daily_closure_reasons),
                        "monthly_avg_eps": monthly_avg_eps,
                        "last_month_avg_eps": last_month_avg_eps,
                        "weekly_avg_eps": list(weekly_avg_eps),
                        "total_traffic": total_traffic,
                        "destination_addresses": list(destination_addresses),
                        "top_destination_connections": list(
                            top_destination_connections
                        ),
                        "daily_event_count": list(daily_event_count),
                    },
                },
                status=200,
            )

        except Exception as e:
            logger.error(f"Error in IncidentReportView: {str(e)}")
            return Response({"error": str(e)}, status=500)


class SourceIPGeoLocationListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        records = SourceIPGeoLocation.objects.all().order_by("-created_at")[:50]
        serializer = SourceIPGeoLocationSerializer(records, many=True)
        return Response(serializer.data)


class FileTypeChoicesView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]
    """
    Returns all file type choices.
    """

    def get(self, request):
        choices = [
            {"id": choice.value, "name": choice.label} for choice in FileTypeChoices
        ]
        return Response(choices)


class DownloadIncidentsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]
    """
    Download incidents data in PDF or Excel format based on IncidentsView logic.
    Filters out false positives and supports date range filtering.
    """

    def get(self, request):
        try:
            # Step 1: Get current tenant
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)

        # Step 2: Check for active SOAR integration
        soar_integrations = tenant.company.integrations.filter(
            integration_type=IntegrationTypes.SOAR_INTEGRATION,
            soar_subtype=SoarSubTypes.CORTEX_SOAR,
            status=True,
        )

        if not soar_integrations.exists():
            return Response(
                {"error": "No active SOAR integration configured for tenant."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Step 3: Get SOAR tenant IDs
        soar_tenants = tenant.company.soar_tenants.all()
        if not soar_tenants:
            return Response({"error": "No SOAR tenants found."}, status=404)

        soar_ids = [t.id for t in soar_tenants]

        # Step 4: Parse query parameters
        start_date_str = request.query_params.get("start_date")
        end_date_str = request.query_params.get("end_date")
        file_type = request.query_params.get("file_type")

        # Step 5: Validate required parameters
        if not start_date_str or not end_date_str:
            return Response(
                {"error": "Both start_date and end_date are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not file_type:
            return Response(
                {"error": "file_type parameter is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Step 6: Validate file_type
        try:
            file_type_choice = FileTypeChoices(int(file_type))
        except ValueError:
            valid_choices = [choice.value for choice in FileTypeChoices]
            return Response(
                {
                    "error": f"Invalid file_type. Must be one of: {', '.join(valid_choices)}"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Step 7: Parse and validate dates
        date_format = "%Y-%m-%d"
        try:
            start_date = datetime.strptime(start_date_str, date_format).date()
            end_date = datetime.strptime(end_date_str, date_format).date()
        except ValueError:
            return Response(
                {"error": "Invalid date format. Use YYYY-MM-DD."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Step 8: Validate date range
        if end_date < start_date:
            return Response(
                {"error": "end_date cannot be before start_date."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Step 9: Build filters (exclude false positives, include only true positives)
        filters = Q(cortex_soar_tenant__in=soar_ids)
        filters &= (
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

        # Step 10: Apply date filters
        filters &= Q(created__date__gte=start_date)
        filters &= Q(created__date__lte=end_date)

        # Step 11: Query incidents
        try:
            queryset = (
                DUCortexSOARIncidentFinalModel.objects.filter(filters)
                .values(
                    "id",
                    "db_id",
                    "account",
                    "name",
                    "status",
                    "incident_priority",
                    "occured",
                    "mitre_tactic",
                    "mitre_technique",
                )
                .order_by("-created")
            )

            # Step 12: Process incidents for offense data
            incidents = []
            for row in queryset:
                if row["occured"]:
                    try:
                        dt_utc = row["occured"]
                        if not isinstance(dt_utc, datetime):
                            dt_utc = datetime.fromisoformat(str(dt_utc))
                        dt_plus_4 = dt_utc + timedelta(hours=4)
                        occured_at_str = dt_plus_4.strftime("%Y-%m-%d %I:%M %p")
                    except Exception:
                        occured_at_str = "N/A"
                else:
                    occured_at_str = "N/A"
                status_label = "OPEN" if int(row["status"]) == 1 else "CLOSED"

                incidents.append(
                    {
                        "ID": str(row["db_id"]),
                        "ACCOUNT": row["account"],
                        "NAME": row["name"],
                        "STATUS": status_label,
                        "INCIDENT_PRIORITY": row["incident_priority"],
                        "OCCURED_AT": occured_at_str,
                        "MITRE_TACTIC": row["mitre_tactic"],
                        "MITRE_TECHNIQUE": row["mitre_technique"],
                    }
                )

            if not incidents:
                return Response(
                    {"error": "No incidents found for the specified date range."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Step 13: Generate file based on file_type
            # if file_type_choice == FileTypeChoices.PDF:
            #     return self._generate_pdf(incidents, start_date, end_date)
            if file_type_choice == FileTypeChoices.EXCEL:
                return self._generate_excel(incidents, start_date, end_date)
            else:
                return Response(
                    {"error": "Unsupported file type."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        except Exception as e:
            logger.error("Error in DownloadIncidentsView: %s", str(e))
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _generate_pdf(self, incidents, start_date, end_date):
        """Generate PDF file with incidents data using HTML template."""
        try:
            # Resolve static file paths and log them
            logo_url = static("images/logo.png")
            header_bg_url = static("images/report-header-bg.svg")

            # Convert URLs to absolute file system paths for WeasyPrint
            logo_path = os.path.join(settings.BASE_DIR, "static", "images", "logo.png")
            header_bg_path = os.path.join(
                settings.BASE_DIR, "static", "images", "report-header-bg.svg"
            )

            logger.info(f"Resolved logo URL: {logo_url} -> Path: {logo_path}")
            logger.info(
                f"Resolved header background URL: {header_bg_url} -> Path: {header_bg_path}"
            )

            html_content = render_to_string(
                "pdf_report_template.html",
                {
                    "incidents": incidents,
                    "start_date": start_date,
                    "end_date": end_date,
                    "total_incidents": len(incidents),
                    "logo_path": f"file://{os.path.join(settings.BASE_DIR, 'static', 'images', 'logo.png')}",
                    "header_bg_path": f"file://{os.path.join(settings.BASE_DIR, 'static', 'images', 'report-header-bg.svg')}",
                },
            )

            # Generate PDF, telling WeasyPrint where to find static files
            pdf_file = HTML(
                string=html_content,
                base_url=settings.BASE_DIR,  # Allows relative URLs to be resolved from your project root
            ).write_pdf()

            response = HttpResponse(pdf_file, content_type="application/pdf")
            filename = f"incidents_report_{start_date}_to_{end_date}.pdf"
            response["Content-Disposition"] = f'attachment; filename="{filename}"'
            return response

        except Exception as e:
            logger.error(f"Error generating PDF: {str(e)}")
            return Response(
                {"error": "Failed to generate PDF file."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _generate_excel(self, incidents, start_date, end_date):
        """Generate Excel file with incidents data"""
        try:
            # Convert to DataFrame
            df = pd.DataFrame(incidents)

            # Create Excel file in memory
            buffer = io.BytesIO()
            with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
                df.to_excel(writer, sheet_name="Incidents", index=False)

                # Get the worksheet to apply formatting
                worksheet = writer.sheets["Incidents"]

                # Auto-adjust column widths
                for column in worksheet.columns:
                    max_length = 0
                    column_letter = column[0].column_letter
                    for cell in column:
                        try:
                            if cell.value and len(str(cell.value)) > max_length:
                                max_length = len(str(cell.value))
                        except Exception:
                            logger.error(".")
                    adjusted_width = min(max_length + 2, 50)  # Prevent too wide columns
                    worksheet.column_dimensions[column_letter].width = adjusted_width

            buffer.seek(0)

            response = HttpResponse(
                buffer.getvalue(),
                content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
            filename = f"incidents_report_{start_date}_to_{end_date}.xlsx"
            response["Content-Disposition"] = f'attachment; filename="{filename}"'
            return response

        except Exception as e:
            logger.error(f"Error generating Excel: {str(e)}")
            return Response(
                {"error": "Failed to generate Excel file."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


def get_incidents_trend(filter_type, filters):
    if filter_type == FilterType.WEEK:
        time_trunc = TruncDay("occured")
    elif filter_type == FilterType.MONTH:
        time_trunc = TruncWeek("occured")
    elif filter_type == FilterType.CUSTOM_RANGE:
        time_trunc = TruncDate("occured")

    incident_trend_qs = (
        DUCortexSOARIncidentFinalModel.objects.filter(filters)
        .annotate(interval=time_trunc)
        .values("interval")
        .annotate(
            reported=Count("id"),
            resolved=Count("id", filter=Q(status="2")),
        )
        .order_by("interval")
    )

    incident_closure_trends = []
    skip_once_done = False
    for entry in incident_trend_qs:
        if filter_type == FilterType.MONTH:
            # Week format
            if len(incident_trend_qs) > 5 and not skip_once_done:
                skip_once_done = True
                continue
            week_num = len(incident_closure_trends) + 1
            interval_str = f"Week {week_num} ({entry['interval'].strftime('%Y-%m-%d')})"
        else:
            interval_str = entry["interval"].strftime("%Y-%m-%d")

        incident_closure_trends.append(
            {
                "interval": interval_str,
                "reported": entry["reported"],
                "resolved": entry["resolved"],
                "pending": entry["reported"] - entry["resolved"],
            }
        )

    return incident_closure_trends


class DetailedIncidentReport(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        pass

        try:
            # Step 1: Get current tenant
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)

        # Step 2: Check for active SOAR integration
        soar_integrations = tenant.company.integrations.filter(
            integration_type=IntegrationTypes.SOAR_INTEGRATION,
            soar_subtype=SoarSubTypes.CORTEX_SOAR,
            status=True,
        )

        if not soar_integrations.exists():
            return Response(
                {"error": "No active SOAR integration configured for tenant."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Step 3: Get SOAR tenant IDs
        soar_tenants = tenant.company.soar_tenants.all()
        if not soar_tenants:
            return Response({"error": "No SOAR tenants found."}, status=404)

        soar_ids = [t.id for t in soar_tenants]

        filter_type = request.query_params.get("filter_type", FilterType.WEEK.value)
        if filter_type is not None:
            try:
                filter_type = int(filter_type)
            except ValueError:
                return Response({"error": "Invalid filter_type."}, status=400)

        filters = Q(cortex_soar_tenant_id__in=soar_ids) & (
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

        # false_postive_filter = Q(itsm_sync_status__iexact="Done")

        now = timezone.now()
        # start_time = end_time = None
        start_date_str = request.query_params.get("start_date")
        end_date_str = request.query_params.get("end_date")

        try:
            filter_type = FilterType(int(filter_type))
            if filter_type == FilterType.WEEK:
                start_date = now - timedelta(days=7)
                filters &= Q(created__date__gte=start_date)
            elif filter_type == FilterType.MONTH:
                start_date = now - timedelta(days=30)
                filters &= Q(created__date__gte=start_date)
            elif filter_type == FilterType.CUSTOM_RANGE:
                start_date_str = request.query_params.get("start_date")
                end_date_str = request.query_params.get("end_date")
                if start_date_str and end_date_str:
                    try:
                        start_date = datetime.strptime(
                            start_date_str, "%Y-%m-%d"
                        ).date()
                        end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
                        filters &= Q(created__date__gte=start_date) & Q(
                            created__date__lte=end_date
                        )
                        if start_date > end_date:
                            return Response(
                                {
                                    "error": "Start date cannot be greater than end date."
                                },
                                status=400,
                            )
                        time_to_check = end_date - start_date
                        if time_to_check.days < 7:
                            return Response(
                                {"error": "Custom range must be at least 7 days."},
                                status=400,
                            )
                    except ValueError:
                        return Response(
                            {"error": "Invalid date format. Use YYYY-MM-DD."},
                            status=400,
                        )
            else:
                return Response({"error": "Unsupported filter"}, status=400)
        except Exception:
            return Response({"error": "Invalid filter_type."}, status=400)

        priority_wise_counts = (
            DUCortexSOARIncidentFinalModel.objects.filter(filters)
            .values("incident_priority")
            .annotate(
                total=Count("id"),
                open_count=Count("id", filter=Q(status="1")),  # status 1 = open
                closed_count=Count("id", filter=Q(status="2")),  # status 2 = closed
            )
            .order_by("-total")
        )

        if not priority_wise_counts:
            return Response({"error": "No incidents found."}, status=404)

        all_severities = {
            SlaLevelChoices.P1.label: 0,
            SlaLevelChoices.P2.label: 0,
            SlaLevelChoices.P3.label: 0,
            SlaLevelChoices.P4.label: 0,
        }

        # Fill in counts from query result
        for row in priority_wise_counts:
            all_severities[row["incident_priority"]] = row["total"]

        # Convert to desired list format
        severity_of_incidents = [
            {"incident_priority": priority, "total": total}
            for priority, total in all_severities.items()
        ]

        incident_counts = DUCortexSOARIncidentFinalModel.objects.filter(
            filters
        ).aggregate(
            total=Count("id"),
            # open_count=Count("id", filter=Q(status="1")),
            closed_count=Count("id", filter=Q(status="2")),
        )

        total_incidents_raised = incident_counts

        # Use case logic using extract_use_case (same as updated ConsolidatedReport)
        from collections import Counter

        # Step 1: Use ORM to get incident names efficiently with filters
        incident_names = (
            DUCortexSOARIncidentFinalModel.objects.filter(filters)
            .filter(name__isnull=False)
            .exclude(name__exact="")
            .values_list("name", flat=True)
        )

        # Step 2: Clean incident names and count occurrences
        incident_name_counts = Counter()
        for name in incident_names:
            cleaned_name = extract_use_case(
                name
            )  # <-- same function as ConsolidatedReport
            if cleaned_name:
                incident_name_counts[cleaned_name] += 1

        # Step 3: Get top 5 most frequent use cases
        top_use_cases = incident_name_counts.most_common(5)

        # Step 4: Build priority breakdown for each top use case
        top_5_use_cases_data = []
        all_incidents_data = (
            DUCortexSOARIncidentFinalModel.objects.filter(filters)
            .filter(name__isnull=False)
            .exclude(name__exact="")
            .values("name", "incident_priority")
        )

        for use_case, count in top_use_cases:
            priority_breakdown = {}

            for incident in all_incidents_data:
                cleaned_name = extract_use_case(incident["name"])
                if cleaned_name == use_case:
                    priority = incident["incident_priority"] or "Unknown"
                    priority_breakdown[priority] = (
                        priority_breakdown.get(priority, 0) + 1
                    )

            # Select most common priority (or Unknown if none found)
            most_common_priority = (
                max(priority_breakdown, key=priority_breakdown.get)
                if priority_breakdown
                else "Unknown"
            )

            top_5_use_cases_data.append(
                {
                    "use_case": use_case,
                    "incident_priority": most_common_priority,
                    "count": count,
                }
            )

        incident_closure_trends = get_incidents_trend(filter_type, filters)

        data = {
            "severity_of_incidents": severity_of_incidents,
            "total_incidents_raised": total_incidents_raised,
            "sla_stats": priority_wise_counts,
            "top_use_cases": top_5_use_cases_data,
            "incident_clousure_trend": incident_closure_trends
            # "sla_metrics":sla_f_metrics
        }

        return Response(data, status=status.HTTP_200_OK)


class ConsolidatedReport(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        from django.db.models.functions import TruncWeek

        try:
            # Step 1: Get current tenant
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)

        # Step 2: Check for active SOAR integration
        soar_integrations = tenant.company.integrations.filter(
            integration_type=IntegrationTypes.SOAR_INTEGRATION,
            soar_subtype=SoarSubTypes.CORTEX_SOAR,
            status=True,
        )

        if not soar_integrations.exists():
            return Response(
                {"error": "No active SOAR integration configured for tenant."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Step 3: Get SOAR tenant IDs
        soar_tenants = tenant.company.soar_tenants.all()
        if not soar_tenants:
            return Response({"error": "No SOAR tenants found."}, status=404)

        soar_ids = [t.id for t in soar_tenants]

        siem_integrations = tenant.company.integrations.filter(
            integration_type=IntegrationTypes.SIEM_INTEGRATION,
            siem_subtype=SiemSubTypes.IBM_QRADAR,
            status=True,
        )
        if not siem_integrations.exists():
            return Response(
                {"error": "No active SIEM integration configured for tenant."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        collector_ids = (
            TenantQradarMapping.objects.filter(company=tenant.company)
            .prefetch_related("event_collectors")
            .values_list("event_collectors__id", flat=True)
        )
        if not collector_ids:
            return Response(
                {"detail": "No Event Collectors mapped to this tenant."},
                status=status.HTTP_404_NOT_FOUND,
            )

        filter_type = request.query_params.get("filter_type", FilterType.WEEK.value)
        if filter_type is not None:
            try:
                filter_type = int(filter_type)
            except ValueError:
                return Response({"error": "Invalid filter_type."}, status=400)

        # Build True Positive and False Positive filters (same as AllIncidentsView and DashboardView)
        # Base filters for True Positives (Ready incidents with all required fields)
        true_positive_filters = Q(cortex_soar_tenant_id__in=soar_ids) & (
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

        # Base filters for False Positives (Done incidents)
        false_positive_filters = Q(cortex_soar_tenant_id__in=soar_ids) & Q(
            itsm_sync_status__iexact="Done"
        )

        # Combine both True Positives and False Positives
        filters = true_positive_filters | false_positive_filters

        now = timezone.now()
        start_date_str = request.query_params.get("start_date")
        end_date_str = request.query_params.get("end_date")

        try:
            filter_type = FilterType(int(filter_type))
            if filter_type == FilterType.TODAY:
                start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
                filters &= Q(created__date=start_date.date())
                start_time = now.replace(hour=0, minute=0, second=0, microsecond=0)
                time_trunc = TruncHour("created_at")
            elif filter_type == FilterType.WEEK:
                start_date = now - timedelta(days=7)
                filters &= Q(created__date__gte=start_date.date())
                start_time = now - timedelta(days=6)
                time_trunc = TruncDay("created_at")
            elif filter_type == FilterType.MONTH:
                start_date = now - timedelta(days=30)
                filters &= Q(created__date__gte=start_date.date())
                start_time = now - timedelta(days=28)
                time_trunc = TruncWeek("created_at")
            elif filter_type == FilterType.CUSTOM_RANGE:
                start_date_str = request.query_params.get("start_date")
                end_date_str = request.query_params.get("end_date")
                if start_date_str and end_date_str:
                    try:
                        start_date = datetime.strptime(
                            start_date_str, "%Y-%m-%d"
                        ).date()
                        end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
                        filters &= Q(created__date__gte=start_date) & Q(
                            created__date__lte=end_date
                        )
                        if start_date > end_date:
                            return Response(
                                {
                                    "error": "Start date cannot be greater than end date."
                                },
                                status=400,
                            )
                        start_time = datetime.strptime(start_date_str, "%Y-%m-%d")
                        end_time = datetime.strptime(
                            end_date_str, "%Y-%m-%d"
                        ) + timedelta(days=1)
                    except ValueError:
                        return Response(
                            {"error": "Invalid date format. Use YYYY-MM-DD."},
                            status=400,
                        )
                    time_trunc = TruncDate("created_at")
                else:
                    return Response(
                        {
                            "error": "Custom range requires both start_date and end_date."
                        },
                        status=400,
                    )
            else:
                return Response(
                    {
                        "error": "Unsupported filter_type. Use 1=Today, 2=Week, 3=Month, 9=Custom Range."
                    },
                    status=400,
                )
        except Exception:
            return Response({"error": "Invalid filter_type."}, status=400)

        priority_wise_counts = (
            DUCortexSOARIncidentFinalModel.objects.filter(filters)
            .values("incident_priority")
            .annotate(
                total=Count("id"),
                open_count=Count("id", filter=Q(status="1")),  # status 1 = open
                closed_count=Count("id", filter=Q(status="2")),  # status 2 = closed
            )
            .order_by("-total")
        )

        if not priority_wise_counts:
            return Response({"error": "No incidents found."}, status=404)

        all_severities = {
            SlaLevelChoices.P1.label: 0,
            SlaLevelChoices.P2.label: 0,
            SlaLevelChoices.P3.label: 0,
            SlaLevelChoices.P4.label: 0,
        }

        # Fill in counts from query result
        for row in priority_wise_counts:
            all_severities[row["incident_priority"]] = row["total"]

        # Convert to desired list format
        severity_of_incidents = [
            {"incident_priority": priority, "total": total}
            for priority, total in all_severities.items()
        ]

        incident_counts = DUCortexSOARIncidentFinalModel.objects.filter(
            filters
        ).aggregate(
            total=Count("id"),
            # open_count=Count("id", filter=Q(status="1")),
            closed_count=Count("id", filter=Q(status="2")),
        )

        total_incidents_raised = incident_counts

        # Existing assets query
        all_assets = IBMQradarAssests.objects.filter(
            event_collector_id__in=collector_ids
        ).select_related("event_collector", "log_source_type")

        # Device coverage counts
        total_assets = all_assets.count()
        active_assets = all_assets.filter(is_active=True).count()

        # Per log_source_type counters
        log_source_stats = defaultdict(
            lambda: {"integrated": 0, "reporting": 0, "non_reporting": 0}
        )

        for asset in all_assets:
            log_source_name = (
                asset.log_source_type.name if asset.log_source_type else "Unknown"
            )

            log_source_stats[log_source_name]["integrated"] += 1
            if asset.is_active:
                log_source_stats[log_source_name]["reporting"] += 1
            else:
                log_source_stats[log_source_name]["non_reporting"] += 1

            # Convert defaultdict to list for JSON
            log_source_stats_list = [
                {"log_source_type": k, **v} for k, v in log_source_stats.items()
            ]

            device_coverage = {
                "integrated_assets": total_assets,
                "reporting_assets": active_assets,
            }
        from collections import Counter

        # Step 1: Use ORM to get incident names efficiently with filters
        incident_names = (
            DUCortexSOARIncidentFinalModel.objects.filter(filters)
            .filter(name__isnull=False)
            .exclude(name__exact="")
            .values_list("name", flat=True)
        )

        # Step 2: Clean incident names and count occurrences
        incident_name_counts = Counter()
        for name in incident_names:
            cleaned_name = extract_use_case(
                name
            )  # <-- same function as UseCaseIncidentsView
            if cleaned_name:
                incident_name_counts[cleaned_name] += 1

        # Step 3: Get top N most frequent use cases (5 or 10)
        top_use_cases = incident_name_counts.most_common(5)  # or .most_common(10)

        # Step 4: Build priority breakdown for each top use case
        top_use_cases_data = []
        all_incidents_data = (
            DUCortexSOARIncidentFinalModel.objects.filter(filters)
            .filter(name__isnull=False)
            .exclude(name__exact="")
            .values("name", "incident_priority")
        )

        for use_case, count in top_use_cases:
            priority_breakdown = {}

            for incident in all_incidents_data:
                cleaned_name = extract_use_case(incident["name"])
                if cleaned_name == use_case:
                    priority = incident["incident_priority"] or "Unknown"
                    priority_breakdown[priority] = (
                        priority_breakdown.get(priority, 0) + 1
                    )

            # Select most common priority (or Unknown if none found)
            most_common_priority = (
                max(priority_breakdown, key=priority_breakdown.get)
                if priority_breakdown
                else "Unknown"
            )

            top_use_cases_data.append(
                {
                    "use_case": use_case,
                    "incident_priority": most_common_priority,
                    "count": count,
                }
            )

        qradar_tenant_ids = tenant.company.qradar_mappings.values_list(
            "qradar_tenant__id", flat=True
        )

        filter_kwargs = {"domain_id__in": qradar_tenant_ids}
        if filter_type == FilterType.CUSTOM_RANGE:
            filter_kwargs["created_at__range"] = (start_time, end_time)
        else:
            filter_kwargs["created_at__gte"] = start_time

        # Query EPS data
        eps_data_raw = (
            IBMQradarEPS.objects.filter(**filter_kwargs)
            .annotate(interval=time_trunc)
            .values("interval", "domain__name")
            .annotate(average_eps=Avg("average_eps"), peak_eps=Max("peak_eps"))
            .order_by("interval")
        )
        eps_data = []
        for entry in eps_data_raw:
            interval_value = entry["interval"]
            peak_row = (
                IBMQradarEPS.objects.filter(**filter_kwargs)
                .annotate(interval=time_trunc)
                .filter(interval=interval_value, peak_eps=entry["peak_eps"])
                .order_by("created_at")  # get earliest if multiple match
                .first()
            )
            peak_eps_time = (
                peak_row.created_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                if peak_row and peak_row.created_at
                else None
            )
            if filter_type == FilterType.TODAY:
                interval_str = entry["interval"].strftime("%Y-%m-%dT%H:%M:%SZ")
            elif filter_type == FilterType.MONTH:
                # Format as "Week 1", "Week 2", etc.
                week_num = len(eps_data) + 1
                interval_str = f"Week {week_num}"
                date_of_week = entry["interval"].strftime("%Y-%m-%d")
                interval_str += f" ({date_of_week})"
            else:
                interval_str = entry["interval"].strftime("%Y-%m-%d")

            eps_data.append(
                {
                    "interval": interval_str,
                    "average_eps": float(
                        Decimal(entry["average_eps"]).quantize(
                            Decimal("0.01"), rounding=ROUND_HALF_UP
                        )
                    ),
                    "domain": entry["domain__name"],
                    "peak_eps": float(
                        Decimal(entry["peak_eps"]).quantize(
                            Decimal("0.01"), rounding=ROUND_HALF_UP
                        )
                    ),
                    "peak_eps_time": peak_eps_time,
                }
            )

        incident_closure_trends = get_incidents_trend(filter_type, filters)

        data = {
            "severity_of_incidents": severity_of_incidents,
            "total_incidents_raised": total_incidents_raised,
            "device_coverage": device_coverage,
            "log_source_stats": log_source_stats_list,
            "sla_stats": priority_wise_counts,
            "top_use_cases": top_use_cases_data,
            "eps_data": eps_data,
            "incident_clousure_trend": incident_closure_trends
            # "sla_metrics":sla_f_metrics
        }

        return Response(data, status=status.HTTP_200_OK)


class DetailedEPSReportAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        from django.db.models.functions import TruncWeek
        from pytz import timezone as pytz_timezone

        try:
            filter_value = int(
                request.query_params.get("filter_type", FilterType.WEEK.value)
            )
            # Validate that only supported filter types are used
            if filter_value not in [
                FilterType.TODAY.value,
                FilterType.WEEK.value,
                FilterType.MONTH.value,
                FilterType.CUSTOM_RANGE.value,
            ]:
                return Response(
                    {
                        "error": "Unsupported filter_type. Use 1 (Today), 2 (Week), 3 (Month), or 9 (Custom Range)."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            filter_enum = FilterType(filter_value)
        except (ValueError, KeyError):
            return Response(
                {"error": "Invalid filter value."}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response(
                {"error": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
            )

        now = timezone.now()

        # Time range & truncation logic (limited to supported filter types)
        if filter_enum == FilterType.TODAY:
            dubai_tz = pytz_timezone("Asia/Dubai")
            dubai_now = now.astimezone(dubai_tz)
            dubai_midnight = dubai_now.replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            # Convert back to UTC for filtering the UTC-based DB
            start_time = dubai_midnight.astimezone(pytz_timezone("UTC"))
            time_trunc = TruncHour("created_at")
        elif filter_enum == FilterType.WEEK:
            start_time = now - timedelta(days=6)
            time_trunc = TruncDay("created_at")
        elif filter_enum == FilterType.MONTH:
            # Get start of current month and show 4 weeks (28 days back from now)
            start_time = now - timedelta(days=28)
            time_trunc = TruncWeek("created_at")  # Group by week to get 4 data points
        elif filter_enum == FilterType.CUSTOM_RANGE:
            start_str = request.query_params.get("start_date")
            end_str = request.query_params.get("end_date")
            if not start_str or not end_str:
                return Response(
                    {"error": "Custom range requires both start_date and end_date."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            try:
                start_time = datetime.strptime(start_str, "%Y-%m-%d")
                end_time = datetime.strptime(end_str, "%Y-%m-%d") + timedelta(days=1)
                if start_time > end_time:
                    return Response(
                        {"error": "Start date must be before end date."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            except (ValueError, TypeError):
                return Response(
                    {"error": "Invalid custom date format. Use YYYY-MM-DD."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            time_trunc = TruncDate("created_at")
        else:
            return Response(
                {
                    "error": "Unsupported filter_type. Use 1 (Today), 2 (Week), 3 (Month), or 9 (Custom Range)."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Domain mapping
        qradar_tenant_ids = tenant.company.qradar_mappings.values_list(
            "qradar_tenant__id", flat=True
        )

        # Filtering logic
        filter_kwargs = {"domain_id__in": qradar_tenant_ids}
        if filter_enum == FilterType.CUSTOM_RANGE:
            filter_kwargs["created_at__range"] = (start_time, end_time)
        else:
            filter_kwargs["created_at__gte"] = start_time

        # Query EPS data
        eps_data_raw = (
            IBMQradarEPS.objects.filter(**filter_kwargs)
            .annotate(interval=time_trunc)
            .values("interval", "domain__name")
            .annotate(average_eps=Avg("average_eps"), peak_eps=Max("peak_eps"))
            .order_by("interval")
        )

        # Format EPS data with improved interval formatting
        eps_data = []
        for entry in eps_data_raw:
            interval_value = entry["interval"]
            peak_row = (
                IBMQradarEPS.objects.filter(**filter_kwargs)
                .annotate(interval=time_trunc)
                .filter(interval=interval_value, peak_eps=entry["peak_eps"])
                .order_by("created_at")  # get earliest if multiple match
                .first()
            )
            peak_eps_time = (
                peak_row.created_at if peak_row and peak_row.created_at else None
            )

            # peak_dt = peak_eps_time + timedelta(hours=4)
            peak_str = peak_eps_time.strftime("%Y-%m-%dT%H:%M:%SZ")

            if filter_enum == FilterType.TODAY:
                interval = entry["interval"]
                new_dt = interval + timedelta(hours=4)
                interval_str = new_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                # interval_str = entry["interval"].strftime("%Y-%m-%dT%H:%M:%SZ")
            elif filter_enum == FilterType.MONTH:
                # Format as "Week 1", "Week 2", etc.
                week_num = len(eps_data) + 1
                interval_str = f"Week {week_num}"
                date_of_week = entry["interval"].strftime("%Y-%m-%d")
                interval_str += f" ({date_of_week})"
            else:
                interval_str = entry["interval"].strftime("%Y-%m-%d")

            eps_data.append(
                {
                    "interval": interval_str,
                    "average_eps": float(
                        Decimal(entry["average_eps"]).quantize(
                            Decimal("0.01"), rounding=ROUND_HALF_UP
                        )
                    ),
                    "domain": entry["domain__name"],
                    "peak_eps": float(
                        Decimal(entry["peak_eps"]).quantize(
                            Decimal("0.01"), rounding=ROUND_HALF_UP
                        )
                    ),
                    "peak_eps_time": peak_str,
                }
            )

        return Response(
            {
                "eps_data": eps_data,
            },
            status=status.HTTP_200_OK,
        )


class AssetReportView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        """
        Asset Report endpoint providing device coverage statistics and log source breakdown

        Provides comprehensive asset reporting with:
        - Device coverage statistics (from ConsolidatedReport)
        - Per log source type statistics
        """
        try:
            # Step 1: Validate tenant
            tenant = Tenant.objects.select_related("tenant").get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response(
                {"detail": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
            )

        try:
            # Step 2: Check for active SIEM integration
            siem_integrations = tenant.company.integrations.filter(
                integration_type=IntegrationTypes.SIEM_INTEGRATION,
                siem_subtype=SiemSubTypes.IBM_QRADAR,
                status=True,
            )
            if not siem_integrations.exists():
                return Response(
                    {"error": "No active SIEM integration configured for tenant."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Step 3: Get mapped collector IDs
            collector_ids = (
                TenantQradarMapping.objects.filter(company=tenant.company)
                .prefetch_related("event_collectors")
                .values_list("event_collectors__id", flat=True)
            )
            if not collector_ids:
                return Response(
                    {"detail": "No Event Collectors mapped to this tenant."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Step 4: Get ALL assets for device coverage calculations
            all_assets = IBMQradarAssests.objects.filter(
                event_collector_id__in=collector_ids
            ).select_related("event_collector", "log_source_type")

            # Device coverage counts
            total_assets = all_assets.count()
            active_assets = all_assets.filter(is_active=True).count()

            # Per log_source_type counters
            log_source_stats = defaultdict(
                lambda: {"integrated": 0, "reporting": 0, "non_reporting": 0}
            )

            for asset in all_assets:
                log_source_name = (
                    asset.log_source_type.name if asset.log_source_type else "Unknown"
                )

                log_source_stats[log_source_name]["integrated"] += 1
                if asset.is_active:
                    log_source_stats[log_source_name]["reporting"] += 1
                else:
                    log_source_stats[log_source_name]["non_reporting"] += 1

            # Convert defaultdict to list for JSON
            log_source_stats_list = [
                {"log_source_type": k, **v} for k, v in log_source_stats.items()
            ]

            device_coverage = {
                "integrated_assets": total_assets,
                "reporting_assets": active_assets,
            }

            response_data = {
                "device_coverage": device_coverage,
                "log_source_stats": log_source_stats_list,
            }

            return Response(response_data)

        except Exception as e:
            logger.error(f"Error in AssetReportView: {str(e)}", exc_info=True)
            return Response(
                {"error": "An unexpected error occurred."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class AssetCountsView(APIView):
    """
    API endpoint to get asset counts (total, active, inactive) from the assets table.
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        try:
            # Get current tenant
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response(
                {"error": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
            )

        try:
            # Get SOAR tenants for this tenant
            soar_tenants = tenant.company.soar_tenants.all()
            if not soar_tenants:
                return Response(
                    {"error": "No SOAR tenants found."},
                    status=status.HTTP_404_NOT_FOUND,
                )
            [t.id for t in soar_tenants]

            # Get mapped collector IDs for this tenant
            collector_ids = (
                TenantQradarMapping.objects.filter(company=tenant.company)
                .prefetch_related("event_collectors")
                .values_list("event_collectors__id", flat=True)
            )
            if not collector_ids:
                return Response(
                    {"detail": "No Event Collectors mapped to this tenant."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Base filter for tenant's assets
            base_filter = Q(event_collector_id__in=collector_ids)

            # Get asset counts using the is_active field if available
            # Try to use the is_active field for better performance
            # total_assets = IBMQradarAssests.objects.filter(base_filter).count()
            active_assets = IBMQradarAssests.objects.filter(
                base_filter & Q(is_active=True)
            ).count()
            inactive_assets = IBMQradarAssests.objects.filter(
                base_filter & Q(is_active=False)
            ).count()

            # Prepare response
            response_data = {
                "total_assets": active_assets + inactive_assets,
                "active_assets": active_assets,
                "inactive_assets": inactive_assets,
            }

            return Response(response_data)

        except Exception as e:
            logger.error(f"Error in AssetCountsView: {str(e)}", exc_info=True)
            return Response(
                {"error": "An unexpected error occurred."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
