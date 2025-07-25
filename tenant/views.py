import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal

from django.db.models import (
    Avg,
    Case,
    Count,
    DurationField,
    ExpressionWrapper,
    F,
    FloatField,
    IntegerField,
    Max,
    Min,
    Q,
    Sum,
    When,
)
from django.db.models.functions import ExtractSecond, TruncDate, TruncDay, TruncHour
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.timezone import make_aware
from loguru import logger
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from authentication.permissions import IsAdminUser, IsTenant
from common.constants import SEVERITY_LABELS, FilterType, PaginationConstants
from common.modules.cyware import Cyware
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
from tenant.ibm_qradar_tasks import sync_parent_high_level_category, sync_sensitive_count_wise_data, \
    sync_correlated_events_data, sync_aep_entra_failures_data, sync_allowed_outbound_data, sync_allowed_inbound_data
from tenant.models import (
    Alert,
    CorrelatedEventLog,
    CywareAlertDetails,
    CywareTenantAlertDetails,
    DailyClosureReasonLog,
    DailyEventCountLog,
    DailyEventLog,
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
    IBMQradarEPSSerializer,
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
        # sync_ibm_admin_eps.delay()
        # sync_successful_logons.delay()
        # sync_dos_event_counts()
        # sync_notes()
        #  sync_correlated_events_data("svc.soc.portal",
        #  "SeonRx##0@55555",
        # "10.225.148.146",
        #  443, 3)
        #
        #  sync_aep_entra_failures_data("svc.soc.portal",
        #                              "SeonRx##0@55555",
        #                              "10.225.148.146",
        #                              443, 3)
        #
        #  sync_allowed_outbound_data("svc.soc.portal",
        #                              "SeonRx##0@55555",
        #                              "10.225.148.146",
        #                              443, 3)

        sync_allowed_inbound_data("svc.soc.portal",
                                    "SeonRx##0@55555",
                                    "10.225.148.146",
                                    443, 3)
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


class GetTenantAssetsList(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        """
        Retrieve IBM QRadar assets with status counts and pagination
        Returns overall active/inactive counts regardless of filters

        Returns:
            {
                "count": filtered_count,
                "total_assets": total_unfiltered_count,
                "active_assets": total_active_unfiltered,
                "inactive_assets": total_inactive_unfiltered,
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

            # Step 4: Get ALL assets first for total counts (unfiltered)
            all_assets = IBMQradarAssests.objects.filter(base_filter).select_related(
                "event_collector", "log_source_type"
            )

            # Calculate TOTAL active/inactive counts (unfiltered) - FIXED LOGIC
            total_active = 0
            total_inactive = 0
            now = timezone.now()

            for asset in all_assets:
                # Use consistent status determination logic
                asset_status = self._get_asset_status(asset, now)
                if asset_status == "SUCCESS":
                    total_active += 1
                else:
                    total_inactive += 1

            # Step 5: Apply request filters for the actual results
            filters = base_filter.copy()

            # Name filter
            if name := request.query_params.get("name"):
                filters &= Q(name__icontains=name)

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

            # Last event date filter (handled in Python due to timestamp conversion)
            last_event_filter = request.query_params.get("last_event_date")

            # Average EPS filter
            if average_eps := request.query_params.get("average_eps"):
                try:
                    filters &= Q(average_eps=float(average_eps))
                except ValueError:
                    return Response(
                        {"error": "Invalid average_eps format. Must be a number."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Get filtered assets
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
                except ValueError:
                    return Response(
                        {"error": "Invalid last_event_date format. Use YYYY-MM-DD."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Apply date range filters if provided
            start_date = self._parse_date(request.query_params.get("start_date"))
            end_date = self._parse_date(request.query_params.get("end_date"))

            if start_date and end_date and start_date > end_date:
                return Response(
                    {"error": "start_date cannot be greater than end_date."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if start_date or end_date:
                filtered_assets = [
                    asset
                    for asset in filtered_assets
                    if (
                        not start_date
                        or (
                            asset.creation_date_converted
                            and asset.creation_date_converted >= start_date
                        )
                    )
                    and (
                        not end_date
                        or (
                            asset.creation_date_converted
                            and asset.creation_date_converted <= end_date
                        )
                    )
                ]

            # Apply status filter if provided - FIXED LOGIC
            if status_filter := request.query_params.get("status"):
                status_filter = status_filter.upper()
                if status_filter not in ["SUCCESS", "ERROR"]:
                    return Response(
                        {
                            "error": "Invalid status value. Must be 'SUCCESS' or 'ERROR'."
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                # Apply consistent status filtering logic
                filtered_assets = [
                    asset
                    for asset in filtered_assets
                    if self._get_asset_status(asset, now) == status_filter
                ]

            # Sort assets by creation date (newest first)
            filtered_assets.sort(
                key=lambda x: x.creation_date_converted or datetime.min.date(),
                reverse=True,
            )

            # Pagination
            paginator = PageNumberPagination()
            paginator.page_size = PaginationConstants.PAGE_SIZE
            result_page = paginator.paginate_queryset(filtered_assets, request)

            # Serialize results with consistent status logic
            serialized_data = []
            for asset in result_page:
                asset_data = IBMQradarAssestsSerializer(asset).data
                # Apply consistent status determination
                asset_data["status"] = self._get_asset_status(asset, now)
                serialized_data.append(asset_data)

            # Prepare response
            response_data = {
                "count": len(filtered_assets),  # Count of filtered assets
                "total_assets": len(all_assets),  # Total unfiltered count
                "active_assets": total_active,  # Unfiltered active count
                "inactive_assets": total_inactive,  # Unfiltered inactive count
                "results": serialized_data,
            }

            # Add pagination links if needed
            if getattr(paginator, "page", None):
                response_data["next"] = paginator.get_next_link()
                response_data["previous"] = paginator.get_previous_link()

            return Response(response_data)

        except Exception as e:
            logger.error(f"Error in GetTenantAssetsList: {str(e)}")
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _get_asset_status(self, asset, now):
        """
        Determine asset status based on enabled flag and last event time
        FIXED: Consistent logic for both counting and filtering
        """
        # If asset is not enabled, it's always ERROR
        if not asset.enabled:
            return "ERROR"

        # If no last event time, it's ERROR
        if not asset.last_event_time:
            return "ERROR"

        try:
            last_event_timestamp = int(asset.last_event_time) / 1000
            last_event_time = datetime.utcfromtimestamp(last_event_timestamp)
            last_event_time = timezone.make_aware(last_event_time)
            time_diff = (now - last_event_time).total_seconds() / 60

            return "ERROR" if time_diff > 15 else "SUCCESS"
        except (ValueError, TypeError):
            return "ERROR"

    def _parse_date(self, date_str):
        """Safe date parsing from string"""
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError:
            raise ValueError("Invalid date format")


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


class SeverityDistributionView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        """
        Retrieve severity distribution (P1-P4) for the authenticated tenant.
        Uses the exact same logic as DashboardView to ensure counts match.

        Returns:
            {
                "severityDistribution": [
                    {"name": "P1", "value": 0},
                    {"name": "P2", "value": 0},
                    {"name": "P3", "value": 0},
                    {"name": "P4", "value": 0}
                ]
            }
        """
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

        try:
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

            # False Positives (Done incidents)
            false_positive_filters = Q(cortex_soar_tenant__in=soar_ids) & Q(
                itsm_sync_status__iexact="Done"
            )

            # Total incidents = True Positives + False Positives (matches DashboardView)
            total_incident_filters = true_positive_filters | false_positive_filters

            # Define our severity levels (P1-P4)
            SEVERITY_LEVELS = {1: "P1", 2: "P2", 3: "P3", 4: "P4"}

            # Get counts for each severity level using the exact same filters as total incidents
            severity_counts = (
                DUCortexSOARIncidentFinalModel.objects.filter(total_incident_filters)
                .values("severity")
                .annotate(count=Count("id"))
            )

            # Convert to dictionary and handle all severity values
            count_dict = {}

            for item in severity_counts:
                severity_val = item["severity"]
                count = item["count"]

                if severity_val in SEVERITY_LEVELS:
                    # Direct mapping for P1-P4 (severity 1-4)
                    count_dict[severity_val] = count_dict.get(severity_val, 0) + count
                elif severity_val is None or severity_val == 0:
                    # Map NULL/0 severity to P4 (lowest priority)
                    count_dict[4] = count_dict.get(4, 0) + count
                elif severity_val > 4:
                    # Map severity > 4 to P4 (lowest priority)
                    count_dict[4] = count_dict.get(4, 0) + count
                else:
                    # For any other unexpected values, map to P4
                    count_dict[4] = count_dict.get(4, 0) + count

            # Build result ensuring all severity levels are included
            result = [
                {
                    "name": severity_name,
                    "value": count_dict.get(severity_value, 0),
                }
                for severity_value, severity_name in SEVERITY_LEVELS.items()
            ]

            return Response({"severityDistribution": result}, status=200)

        except Exception as e:
            logger.error("Error in SeverityDistributionView: %s", str(e))
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


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

        try:
            # Query type distribution using Django ORM
            type_data = (
                DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids
                )
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


class SLAStatusView(APIView):
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
            # Query SLA compliance using Django ORM
            sla_stats = DUCortexSOARIncidentFinalModel.objects.filter(
                cortex_soar_tenant__in=soar_ids, status__in=["Closed", "False Positive"]
            ).aggregate(
                total=Count("id", filter=Q(sla__isnull=False)),
                within_sla=Count(
                    "id",
                    filter=Q(sla__isnull=False)
                    & Q(
                        created__gte=timezone.now()
                        - F("sla") * timezone.timedelta(hours=1)
                    ),
                    output_field=IntegerField(),
                ),
            )

            total = sla_stats["total"] or 0
            within_sla = sla_stats["within_sla"] or 0
            sla_percentage = (within_sla / total * 100) if total > 0 else 100

            # Query most at-risk incidents
            at_risk_qs = (
                DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids,
                    status__in=["Closed", "False Positive"],
                    sla__isnull=False,
                )
                .annotate(
                    # Calculate hours_open as seconds difference / 3600
                    hours_open=ExpressionWrapper(
                        ExtractSecond(timezone.now() - F("created")) / 3600.0,
                        output_field=FloatField(),
                    ),
                    # Calculate hours_remaining as sla - hours_open
                    hours_remaining=ExpressionWrapper(
                        F("sla")
                        - (ExtractSecond(timezone.now() - F("created")) / 3600.0),
                        output_field=FloatField(),
                    ),
                )
                .order_by("hours_remaining")
                .select_related("integration")[:5]  # Limit to 5
            )

            at_risk = []
            severity_map = {1: "P1", 2: "P2", 3: "P3", 4: "P4"}
            for incident in at_risk_qs:
                hours_remaining = incident.hours_remaining
                days_remaining = hours_remaining / 24.0  # Numeric division

                # Determine status
                status_flag = "OK"
                if hours_remaining < 0:
                    status_flag = "Overdue"
                elif hours_remaining < 4:
                    status_flag = "Critical"
                elif hours_remaining < 24:
                    status_flag = "Warning"

                # Map severity to priority
                priority = severity_map.get(incident.severity, "P4")

                at_risk.append(
                    {
                        "id": f"{incident.id}",
                        "name": incident.name,
                        "priority": priority,
                        "remaining": f"{days_remaining:.1f} days"
                        if hours_remaining > 0
                        else "Overdue",
                        "status": status_flag,
                    }
                )

            return Response(
                {
                    "slaCompliance": {
                        "percentage": round(sla_percentage, 1),
                        "withinSla": within_sla,
                        "total": total,
                        "atRiskIncidents": at_risk,
                    }
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error("Error in SLAStatusView: %s", str(e))
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

            # Date calculations
            today = timezone.now().date()
            yesterday = today - timedelta(days=1)
            last_week = today - timedelta(days=7)

            dashboard_data = {}

            # Total Incidents (True Positives + False Positives only)
            if not filter_list or "totalIncidents" in filter_list:
                total_incidents = DUCortexSOARIncidentFinalModel.objects.filter(
                    total_incident_filters
                ).count()

                last_week_count = DUCortexSOARIncidentFinalModel.objects.filter(
                    total_incident_filters, created__date__range=[last_week, yesterday]
                ).count()

                current_week_count = DUCortexSOARIncidentFinalModel.objects.filter(
                    total_incident_filters,
                    created__date__range=[today - timedelta(days=6), today],
                ).count()

                percent_change = self._calculate_percentage_change(
                    current_week_count, last_week_count, "week"
                )

                dashboard_data["totalIncidents"] = {
                    "count": total_incidents,
                    "change": percent_change,
                    "new": DUCortexSOARIncidentFinalModel.objects.filter(
                        total_incident_filters, created__date=today
                    ).count(),
                }

            # Open Incidents (status=1) - Using true positive filters
            if not filter_list or "open" in filter_list:
                open_count = DUCortexSOARIncidentFinalModel.objects.filter(
                    true_positive_filters, status=1
                ).count()

                yesterday_open = DUCortexSOARIncidentFinalModel.objects.filter(
                    true_positive_filters, status=1, created__date=yesterday
                ).count()

                today_open = DUCortexSOARIncidentFinalModel.objects.filter(
                    true_positive_filters, status=1, created__date=today
                ).count()

                percent_change = self._calculate_percentage_change(
                    today_open, yesterday_open, "day"
                )

                dashboard_data["open"] = {"count": open_count, "change": percent_change}

            # Closed Incidents (status=2) - Using true positive filters
            if not filter_list or "closed" in filter_list:
                closed_count = DUCortexSOARIncidentFinalModel.objects.filter(
                    true_positive_filters, status=2
                ).count()

                yesterday_closed = DUCortexSOARIncidentFinalModel.objects.filter(
                    true_positive_filters, status=2, closed__date=yesterday
                ).count()

                today_closed = DUCortexSOARIncidentFinalModel.objects.filter(
                    true_positive_filters, status=2, closed__date=today
                ).count()

                percent_change = self._calculate_percentage_change(
                    today_closed, yesterday_closed, "day"
                )

                dashboard_data["closed"] = {
                    "count": closed_count,
                    "change": percent_change,
                }

            # True Positives (Ready incidents with all required fields)
            if not filter_list or "truePositives" in filter_list:
                tp_count = DUCortexSOARIncidentFinalModel.objects.filter(
                    true_positive_filters
                ).count()

                last_week_tp = DUCortexSOARIncidentFinalModel.objects.filter(
                    true_positive_filters, created__date__range=[last_week, yesterday]
                ).count()

                current_week_tp = DUCortexSOARIncidentFinalModel.objects.filter(
                    true_positive_filters,
                    created__date__range=[today - timedelta(days=6), today],
                ).count()

                percent_change = self._calculate_percentage_change(
                    current_week_tp, last_week_tp, "week"
                )

                dashboard_data["truePositives"] = {
                    "count": tp_count,
                    "change": percent_change,
                }

            # False Positives (Done incidents)
            if not filter_list or "falsePositives" in filter_list:
                fp_count = DUCortexSOARIncidentFinalModel.objects.filter(
                    false_positive_filters
                ).count()

                last_week_fp = DUCortexSOARIncidentFinalModel.objects.filter(
                    false_positive_filters, created__date__range=[last_week, yesterday]
                ).count()

                current_week_fp = DUCortexSOARIncidentFinalModel.objects.filter(
                    false_positive_filters,
                    created__date__range=[today - timedelta(days=6), today],
                ).count()

                percent_change = self._calculate_percentage_change(
                    current_week_fp, last_week_fp, "week"
                )

                dashboard_data["falsePositives"] = {
                    "count": fp_count,
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

    def _calculate_percentage_change(self, current, previous, period="day"):
        """Calculate percentage change with time period indication"""
        if previous == 0:
            return f"0% from previous {period}"

        change = ((current - previous) / previous) * 100
        change = max(-100, min(100, change))  # Bound between -100% and 100%
        direction = "↑" if change >= 0 else "↓"
        return f"{direction} {abs(round(change, 1))}% from previous {period}"


class IncidentsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

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
        start_date_str = request.query_params.get("start_date")
        end_date_str = request.query_params.get("end_date")
        occurred_start_str = request.query_params.get(
            "occurred_start"
        )  # Note: Typo in parameter name (should be 'occurred')
        occurred_end_str = request.query_params.get("occurred_end")
        false_positives = (
            request.query_params.get("false_positives", "").lower() == "true"
        )

        date_format = "%Y-%m-%d"  # Expected format for date inputs

        # Step 5: Initialize filters with Q object
        filters = Q(cortex_soar_tenant__in=soar_ids)

        # Handle false positives filter
        if false_positives:
            # For false positives, we only need to check for Done status
            filters &= Q(itsm_sync_status__iexact="Done")
        else:
            # Original filters for true positives
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

        if severity_filter:
            try:
                severity_value = int(severity_filter)
                filters &= Q(severity=severity_value)
            except ValueError:
                return Response(
                    {"error": "Invalid severity format. Must be an integer."},
                    status=400,
                )

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
                "severity",
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
                if offense_db_id is None:
                    continue
                offense_id = offense_map.get(offense_db_id) if offense_db_id else None

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
                        "severity": row["severity"],
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
                    "severity",
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

            # Build timeline
            timeline = []
            if incident["created"]:
                timeline.append(
                    {
                        "icon": "add_alert",
                        "title": "Incident created",
                        "time": incident["created"].strftime("%I:%M %p"),
                        "description": "System created the incident",
                        "detail": f"Source: {incident['qradar_category'] or 'SIEM Alert'}",
                    }
                )

            if incident["owner"]:
                timeline.append(
                    {
                        "icon": "person",
                        "title": "Assigned",
                        "time": incident["modified"].strftime("%I:%M %p"),
                        "description": f"Incident assigned to {incident['owner']}",
                        "detail": "Action: Changed assignee from Unassigned",
                    }
                )

            if incident["status"] == "Closed" and incident["closed"]:
                timeline.append(
                    {
                        "icon": "task_alt",
                        "title": "Incident closed",
                        "time": incident["closed"].strftime("%I:%M %p"),
                        "description": f"Closed by {incident['closing_user_id'] or 'System'}",
                        "detail": f"Reason: {incident['reason'] or 'Not specified'}",
                    }
                )

            if incident["incident_tta"]:
                timeline.append(
                    {
                        "icon": "schedule",
                        "title": "Incident acknowledged",
                        "time": incident["incident_tta"].strftime("%I:%M %p"),
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

            log_source_types = []
            if incident["log_source_type"]:
                try:
                    log_source_types = (
                        json.loads(incident["log_source_type"])
                        if isinstance(incident["log_source_type"], str)
                        else incident["log_source_type"]
                    )
                except (json.JSONDecodeError, TypeError):
                    log_source_types = []

            # Create related items
            related_items = {"alerts": [], "users": [], "assets": []}

            if incident["list_of_rules_offense"]:
                try:
                    rules = (
                        json.loads(incident["list_of_rules_offense"])
                        if isinstance(incident["list_of_rules_offense"], str)
                        else incident["list_of_rules_offense"]
                    )
                    # Handle list of strings
                    if isinstance(rules, list) and all(
                        isinstance(rule, str) for rule in rules
                    ):
                        for rule in rules[:5]:  # Limit to first 5
                            related_items["alerts"].append(
                                {"title": "Rule", "subtitle": rule or "Unknown Rule"}
                            )
                    # Handle list of dictionaries
                    elif isinstance(rules, list):
                        for rule in rules[:5]:
                            rule_id = (
                                rule.get("id", "Unknown")
                                if isinstance(rule, dict)
                                else "Unknown"
                            )
                            rule_name = (
                                rule.get("name", "Unknown Rule")
                                if isinstance(rule, dict)
                                else str(rule)
                            )
                            related_items["alerts"].append(
                                {"title": f"Rule {rule_id}", "subtitle": rule_name}
                            )
                    else:
                        related_items["alerts"].append(
                            {
                                "title": "Associated Rules",
                                "subtitle": "See incident details",
                            }
                        )
                except (json.JSONDecodeError, TypeError):
                    related_items["alerts"].append(
                        {
                            "title": "Associated Rules",
                            "subtitle": "See incident details",
                        }
                    )

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
            log_source_type_str = (
                ", ".join(log_source_types) if log_source_types else "Unknown"
            )

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
                    "created": (
                        incident["created"].strftime("%Y-%m-%d %I:%M %p")
                        if incident["created"]
                        else "Unknown"
                    ),
                    "modified": (
                        incident["modified"].strftime("%Y-%m-%d %I:%M %p")
                        if incident["modified"]
                        else "Unknown"
                    ),
                    "assignee": (
                        "N/A" if incident["owner"] == " " else incident["owner"]
                    ),
                    "description": incident["name"].strip().split(" ", 1)[1],
                    "customFields": {
                        "phase": incident["incident_phase"] or "Detection",
                        "priority": incident["incident_priority"] or None,
                        "severity": incident["severity"],
                        "sourceIPs": source_ips_str,
                        "logSourceType": log_source_type_str,
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
                        incident["occured"].strftime("%Y-%m-%d %I:%M %p")
                        if incident["occured"]
                        else "Unknown"
                    ),
                    "offense_id": offense_id,
                    "offense_db_id": offense_db_id,
                    "ticket_id": ticket_id,
                    "ticket_db_id": ticket_db_id,
                    "tta": incident["incident_tta"],
                    "ttn": incident["incident_ttn"],
                    "ttdn": incident["incident_ttdn"],
                    "notes": notes_by_user,
                }
            }

            return Response(response, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error in IncidentDetailView: {str(e)}")
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class OffenseStatsAPIView(APIView):
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

            # Step 3: Calculate today's start timestamp (00:00 UTC, May 22, 2025)
            now = timezone.now()

            # Start of today in Django timezone
            today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

            # Convert to milliseconds timestamp
            today_start_timestamp = int(today_start.timestamp() * 1000)
            # Step 4: Compute statistics directly in the database
            stats = IBMQradarOffense.objects.filter(
                Q(assests__id__in=assets) & Q(qradar_tenant_domain__id__in=tenant_ids)
            ).aggregate(
                total_offenses=Count("id"),
                open_offenses=Count(
                    Case(When(~Q(status="CLOSED"), then=1), output_field=IntegerField())
                ),
                high_severity=Count(
                    Case(When(severity__gte=7, then=1), output_field=IntegerField())
                ),
                low_severity=Count(
                    Case(When(severity__lt=4, then=1), output_field=IntegerField())
                ),
                todays_offenses=Count(
                    Case(
                        When(start_time__gt=today_start_timestamp, then=1),
                        output_field=IntegerField(),
                    )
                ),
            )

            # Step 5: Format the response
            response_data = {
                "statistics": {
                    "total_offenses": stats["total_offenses"] or 0,
                    "open_offenses": stats["open_offenses"] or 0,
                    "high_severity": stats["high_severity"] or 0,
                    "low_severity": stats["low_severity"] or 0,
                    "todays_offenses": stats["todays_offenses"] or 0,
                }
            }

            if stats["total_offenses"] == 0:
                response_data[
                    "message"
                ] = "No offenses found for the given assets and tenant."

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


class OffenseDetailsByTenantAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        """
        Retrieve QRadar offenses filtered by:
        - Tenant-specific assets and QRadar tenant domains
        - Optional query parameters: id, db_id, description, severity, status,
          start_date, end_date, start_time_start, start_time_end

        Query Parameters:
            id (int): Exact match on id
            db_id (int): Exact match on db_id
            description (str): Partial match on description (case-insensitive)
            severity (int): Exact match on severity
            status (str): Partial match on status (case-insensitive)
            start_date (YYYY-MM-DD): Offenses created on or after this date
            end_date (YYYY-MM-DD): Offenses created on or before this date
            start_time_start (YYYY-MM-DD): Offenses with start_time on or after this date
            start_time_end (YYYY-MM-DD): Offenses with start_time on or before this date

        Returns:
            Paginated response with count, next, previous, and results
        """
        try:
            # Step 1: Validate tenant
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)

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

        try:
            # Step 3: Get tenant mappings
            mappings = TenantQradarMapping.objects.filter(
                company=tenant.company
            ).values_list("event_collectors__id", "qradar_tenant__id")

            if not mappings:
                return Response(
                    {"error": "No mappings found for the tenant."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            collector_ids, tenant_ids = zip(*mappings)

            # Step 4: Get assets for collectors
            assets = IBMQradarAssests.objects.filter(
                event_collector__id__in=collector_ids
            ).values_list("id", flat=True)

            if not assets:
                return Response(
                    {"error": "No assets found for the given collectors."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Step 5: Build filters
            filters = Q(assests__id__in=assets) & Q(
                qradar_tenant_domain__id__in=tenant_ids
            )

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
                try:
                    db_id_value = int(db_id_filter)
                    filters &= Q(db_id=db_id_value)
                except ValueError:
                    return Response(
                        {"error": "Invalid db_id format. Must be an integer."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Description filter
            description_filter = request.query_params.get("description")
            if description_filter:
                filters &= Q(description__icontains=description_filter)

            # Severity filter
            severity_filter = request.query_params.get("severity")
            if severity_filter:
                try:
                    severity_value = int(severity_filter)
                    filters &= Q(severity=severity_value)
                except ValueError:
                    return Response(
                        {"error": "Invalid severity format. Must be an integer."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Status filter
            status_filter = request.query_params.get("status")
            if status_filter:
                filters &= Q(status__icontains=status_filter)

            # Date filters
            date_format_filter = "%Y-%m-%d"  # e.g., "2025-06-17"
            start_date_str = request.query_params.get("start_date")
            end_date_str = request.query_params.get("end_date")

            if start_date_str:
                try:
                    start_date = datetime.strptime(
                        start_date_str, date_format_filter
                    ).date()
                    filters &= Q(start_date__gte=start_date)
                except ValueError:
                    return Response(
                        {"error": "Invalid start_date format. Use YYYY-MM-DD."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if end_date_str:
                try:
                    end_date = datetime.strptime(
                        end_date_str, date_format_filter
                    ).date()
                    filters &= Q(start_date__lte=end_date)
                except ValueError:
                    return Response(
                        {"error": "Invalid end_date format. Use YYYY-MM-DD."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if start_date_str and end_date_str and end_date < start_date:
                return Response(
                    {"error": "end_date must be after or equal to start_date."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Start time filters (assuming start_time is a Unix timestamp in milliseconds)
            start_time_start_str = request.query_params.get("start_time_start")
            start_time_end_str = request.query_params.get("start_time_end")

            if start_time_start_str:
                try:
                    start_time_start_dt = datetime.strptime(
                        start_time_start_str, date_format_filter
                    )
                    # Convert datetime to Unix timestamp (milliseconds)
                    start_time_start = int(start_time_start_dt.timestamp() * 1000)
                    filters &= Q(start_time__gte=start_time_start)
                except ValueError:
                    return Response(
                        {"error": "Invalid start_time_start format. Use YYYY-MM-DD."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if start_time_end_str:
                try:
                    start_time_end_dt = datetime.strptime(
                        start_time_end_str, date_format_filter
                    )
                    # Convert datetime to Unix timestamp (milliseconds)
                    start_time_end = int(start_time_end_dt.timestamp() * 1000)
                    filters &= Q(start_time__lte=start_time_end)
                except ValueError:
                    return Response(
                        {"error": "Invalid start_time_end format. Use YYYY-MM-DD."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if (
                start_time_start_str
                and start_time_end_str
                and start_time_end < start_time_start
            ):
                return Response(
                    {
                        "error": "start_time_end must be after or equal to start_time_start."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Handle null start_date (exclude or include based on requirement)
            # Option 1: Exclude null start_date records when date filters are applied
            if start_date_str or end_date_str:
                filters &= Q(start_date__isnull=False)

            # Step 6: Query offenses
            offenses = (
                IBMQradarOffense.objects.filter(filters)
                .values(
                    "id",
                    "db_id",
                    "description",
                    "severity",
                    "status",
                    "start_date",
                    "start_time",
                )
                .distinct()
                .order_by("-start_date")
            )

            # Step 7: Pagination
            paginator = PageNumberPagination()
            paginator.page_size = PaginationConstants.PAGE_SIZE
            paginated_offenses = paginator.paginate_queryset(offenses, request)

            # Step 8: Return paginated response
            return paginator.get_paginated_response(
                {"offenses": list(paginated_offenses)}
            )

        except Exception as e:
            logger.error(f"Error in OffenseDetailsByTenantAPIView {str(e)}")
            return Response(
                {"error": f"{str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
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

            # Initialize filters
            filters = Q(assests__id__in=assets) & Q(
                qradar_tenant_domain__id__in=tenant_ids
            )

            # Handle date filtering
            filter_type = request.query_params.get("filter_type")
            start_date = request.query_params.get("start_date")
            end_date = request.query_params.get("end_date")
            db_timezone = timezone.get_fixed_timezone(240)
            now = timezone.now().astimezone(db_timezone)

            def datetime_to_unix(dt):
                return (
                    int(time.mktime(dt.timetuple())) * 1000
                )  # Convert to milliseconds

            if start_date and end_date:
                try:
                    start_date = timezone.make_aware(
                        datetime.strptime(start_date, "%Y-%m-%d"), timezone=db_timezone
                    ).replace(hour=0, minute=0, second=0, microsecond=0)
                    end_date = timezone.make_aware(
                        datetime.strptime(end_date, "%Y-%m-%d"), timezone=db_timezone
                    ).replace(hour=23, minute=59, second=59, microsecond=999999)

                    filters &= Q(start_time__gte=datetime_to_unix(start_date)) & Q(
                        start_time__lte=datetime_to_unix(end_date)
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
                    elif filter_type == FilterType.QUARTER:
                        current_quarter = (now.month - 1) // 3 + 1
                        quarter_start_month = 3 * current_quarter - 2
                        start_date = now.replace(
                            month=quarter_start_month,
                            day=1,
                            hour=0,
                            minute=0,
                            second=0,
                            microsecond=0,
                        )
                        end_date = now.replace(
                            hour=23, minute=59, second=59, microsecond=999999
                        )
                    elif filter_type == FilterType.YEAR:
                        start_date = now.replace(
                            month=1, day=1, hour=0, minute=0, second=0, microsecond=0
                        )
                        end_date = now.replace(
                            hour=23, minute=59, second=59, microsecond=999999
                        )
                    elif filter_type == FilterType.LAST_6_MONTHS:
                        start_date = now - timedelta(days=180)
                        start_date = start_date.replace(
                            hour=0, minute=0, second=0, microsecond=0
                        )
                        end_date = now.replace(
                            hour=23, minute=59, second=59, microsecond=999999
                        )
                    elif filter_type == FilterType.LAST_3_WEEKS:
                        start_date = now - timedelta(weeks=3)
                        start_date = start_date.replace(
                            hour=0, minute=0, second=0, microsecond=0
                        )
                        end_date = now.replace(
                            hour=23, minute=59, second=59, microsecond=999999
                        )
                    elif filter_type == FilterType.LAST_MONTH:
                        # Get first day of last month
                        first_day_this_month = now.replace(day=1)
                        last_day_last_month = first_day_this_month - timedelta(days=1)
                        start_date = last_day_last_month.replace(
                            day=1, hour=0, minute=0, second=0, microsecond=0
                        )
                        end_date = last_day_last_month.replace(
                            hour=23, minute=59, second=59, microsecond=999999
                        )

                    filters &= Q(start_time__gte=datetime_to_unix(start_date)) & Q(
                        start_time__lte=datetime_to_unix(end_date)
                    )
                except Exception as e:
                    return Response(
                        {"error": f"Invalid filter_type: {str(e)}"}, status=400
                    )

            # Step 3: Retrieve offenses with categories field
            offenses = IBMQradarOffense.objects.filter(filters).values("categories")

            # Step 4: Aggregate category counts
            category_counts = Counter()
            for offense in offenses:
                categories = offense["categories"] or []  # Handle null/empty JSONField
                if isinstance(categories, list):  # Ensure it's a list
                    category_counts.update(
                        category for category in categories if category
                    )  # Skip empty strings

            # Step 5: Format the response for graphing
            response_data = [
                {"category": category, "count": count}
                for category, count in category_counts.items()
            ]

            if not response_data:
                return Response(
                    {
                        "message": "No offense categories found for the given assets and tenant.",
                        "categories": [],
                    },
                    status=status.HTTP_200_OK,
                )

            return Response({"categories": response_data}, status=status.HTTP_200_OK)

        except Exception as e:
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
                .values("id", "db_id", "name", "description", "offense_count")[:5]
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


class EPSCountValuesByDomainAPIView(APIView):
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
            qradar_tenant_ids = TenantQradarMapping.objects.filter(
                company=tenant.company
            ).values_list("qradar_tenant__id", flat=True)

            if not qradar_tenant_ids:
                return Response(
                    {"error": "No mappings found for the tenant."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            eps_entries = IBMQradarEPS.objects.filter(domain__in=qradar_tenant_ids)
            sum_eps = eps_entries.aggregate(total_eps=Sum("eps"))["total_eps"] or 0
            serializer = IBMQradarEPSSerializer(
                eps_entries, many=True, context={"request": request}
            )

            mapping = TenantQradarMapping.objects.filter(company=tenant.company).first()

            contracted_volume = mapping.contracted_volume if mapping else None
            contracted_volume_type = mapping.contracted_volume_type if mapping else None
            contracted_volume_type_display = (
                mapping.get_contracted_volume_type_display() if mapping else None
            )

            # Step 4: Return combined response
            return Response(
                {
                    "contracted_volume": contracted_volume,
                    "contracted_volume_type": contracted_volume_type,
                    "contracted_volume_type_display": contracted_volume_type_display,
                    "sum_eps": sum_eps,
                    "eps_data": serializer.data,
                },
                status=200,
            )
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


# class EPSGraphAPIView(APIView):
#     authentication_classes = [JWTAuthentication]
#     permission_classes = [IsTenant]

#     def get(self, request):
#         try:
#             filter_value = int(
#                 request.query_params.get("filter_type", FilterType.TODAY.value)
#             )
#             filter_enum = FilterType(filter_value)
#         except (ValueError, KeyError):
#             return Response(
#                 {"error": "Invalid filter value."},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )

#         try:
#             tenant = Tenant.objects.get(tenant=request.user)
#         except Tenant.DoesNotExist:
#             return Response(
#                 {"error": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
#             )

#         now = timezone.now()

#         # Determine time range and truncation
#         if filter_enum == FilterType.TODAY:
#             start_time = now.replace(hour=0, minute=0, second=0, microsecond=0)
#             time_trunc = TruncHour("created_at")
#         elif filter_enum == FilterType.WEEK:
#             start_time = now - timedelta(days=6)
#             time_trunc = TruncDay("created_at")
#         elif filter_enum == FilterType.MONTH:
#             start_time = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
#             time_trunc = TruncDate("created_at")
#         elif filter_enum == FilterType.YEAR:
#             start_time = now.replace(
#                 month=1, day=1, hour=0, minute=0, second=0, microsecond=0
#             )
#             time_trunc = TruncDate("created_at")
#         elif filter_enum == FilterType.QUARTER:
#             month = (now.month - 1) // 3 * 3 + 1
#             start_time = now.replace(
#                 month=month, day=1, hour=0, minute=0, second=0, microsecond=0
#             )
#             time_trunc = TruncDate("created_at")
#         elif filter_enum == FilterType.LAST_6_MONTHS:
#             start_time = now - timedelta(days=182)
#             time_trunc = TruncDate("created_at")
#         elif filter_enum == FilterType.LAST_3_WEEKS:
#             start_time = now - timedelta(weeks=3)
#             time_trunc = TruncDate("created_at")
#         elif filter_enum == FilterType.LAST_MONTH:
#             first_day_this_month = now.replace(day=1)
#             last_month = first_day_this_month - timedelta(days=1)
#             start_time = last_month.replace(day=1)
#             time_trunc = TruncDate("created_at")
#         elif filter_enum == FilterType.CUSTOM_RANGE:
#             start_str = request.query_params.get("start_date")
#             end_str = request.query_params.get("end_date")
#             try:
#                 start_time = datetime.strptime(start_str, "%Y-%m-%d")
#                 end_time = datetime.strptime(end_str, "%Y-%m-%d") + timedelta(days=1)
#                 if start_time > end_time:
#                     return Response(
#                         {"error": "Start date must be before end date."},
#                         status=status.HTTP_400_BAD_REQUEST,
#                     )
#             except (ValueError, TypeError):
#                 return Response(
#                     {"error": "Invalid custom date format. Use YYYY-MM-DD."},
#                     status=status.HTTP_400_BAD_REQUEST,
#                 )
#             time_trunc = TruncDate("created_at")
#         else:
#             return Response(
#                 {"error": "Unsupported filter."},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )

#         # Get QRadar domain IDs
#         qradar_tenant_ids = tenant.company.qradar_mappings.values_list(
#             "qradar_tenant__id", flat=True
#         )

#         # If custom range, apply both start and end time
#         filter_kwargs = {"domain_id__in": qradar_tenant_ids}
#         if filter_enum == FilterType.CUSTOM_RANGE:
#             filter_kwargs["created_at__range"] = (start_time, end_time)
#         else:
#             filter_kwargs["created_at__gte"] = start_time

#         # Query EPS data
#         eps_data_raw = (
#             IBMQradarEPS.objects.filter(**filter_kwargs)
#             .annotate(interval=time_trunc)
#             .values("interval")
#             .annotate(total_eps=Avg("eps"))
#             .order_by("interval")
#         )

#         eps_data = [
#             {
#                 "interval": entry["interval"],
#                 "total_eps": float(
#                     Decimal(entry["total_eps"]).quantize(
#                         Decimal("0.01"), rounding=ROUND_HALF_UP
#                     )
#                 ),
#             }
#             for entry in eps_data_raw
#         ]

#         # Contracted volume info
#         mapping = TenantQradarMapping.objects.filter(company=tenant.company).first()
#         contracted_volume = mapping.contracted_volume if mapping else None
#         contracted_volume_type = mapping.contracted_volume_type if mapping else None
#         contracted_volume_type_display = (
#             mapping.get_contracted_volume_type_display() if mapping else None
#         )

#         return Response(
#             {
#                 "contracted_volume": contracted_volume,
#                 "contracted_volume_type": contracted_volume_type,
#                 "contracted_volume_type_display": contracted_volume_type_display,
#                 "eps_graph": eps_data,
#             },
#             status=200,
#         )


class EPSGraphAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        try:
            filter_value = int(
                request.query_params.get("filter_type", FilterType.TODAY.value)
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
            start_time = now.replace(hour=0, minute=0, second=0, microsecond=0)
            time_trunc = TruncHour("created_at")
        elif filter_enum == FilterType.WEEK:
            start_time = now - timedelta(days=6)
            time_trunc = TruncDay("created_at")
        elif filter_enum == FilterType.MONTH:
            start_time = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            time_trunc = TruncDate("created_at")
        elif filter_enum == FilterType.YEAR:
            start_time = now.replace(
                month=1, day=1, hour=0, minute=0, second=0, microsecond=0
            )
            time_trunc = TruncDate("created_at")
        elif filter_enum == FilterType.QUARTER:
            month = (now.month - 1) // 3 * 3 + 1
            start_time = now.replace(
                month=month, day=1, hour=0, minute=0, second=0, microsecond=0
            )
            time_trunc = TruncDate("created_at")
        elif filter_enum == FilterType.LAST_6_MONTHS:
            start_time = now - timedelta(days=182)
            time_trunc = TruncDate("created_at")
        elif filter_enum == FilterType.LAST_3_WEEKS:
            start_time = now - timedelta(weeks=3)
            time_trunc = TruncDate("created_at")
        elif filter_enum == FilterType.LAST_MONTH:
            first_day_this_month = now.replace(day=1)
            last_month = first_day_this_month - timedelta(days=1)
            start_time = last_month.replace(day=1)
            time_trunc = TruncDate("created_at")
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
                {"error": "Unsupported filter."}, status=status.HTTP_400_BAD_REQUEST
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

        # Format EPS data
        eps_data = [
            {
                "interval": entry["interval"],
                "average_eps": float(
                    Decimal(entry["average_eps"]).quantize(
                        Decimal("0.01"), rounding=ROUND_HALF_UP
                    )
                ),
                "peak_eps": float(
                    Decimal(entry["peak_eps"]).quantize(
                        Decimal("0.01"), rounding=ROUND_HALF_UP
                    )
                ),
            }
            for entry in eps_data_raw
        ]

        # Contracted volume info
        mapping = TenantQradarMapping.objects.filter(company=tenant.company).first()
        contracted_volume = mapping.contracted_volume if mapping else None
        contracted_volume_type = mapping.contracted_volume_type if mapping else None
        contracted_volume_type_display = (
            mapping.get_contracted_volume_type_display() if mapping else None
        )

        return Response(
            {
                "contracted_volume": contracted_volume,
                "contracted_volume_type": contracted_volume_type,
                "contracted_volume_type_display": contracted_volume_type_display,
                "eps_graph": eps_data,
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

            # Step 4: Apply filters and sort
            queryset = queryset.filter(filters).order_by("-published_time")

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


class RecentIncidentsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        """
        Retrieve two lists: up to 5 incidents with status='1' (Open) and up to 5 incidents
        with status='2' (Closed), ordered by created date (descending), filtered by SOAR
        tenant IDs and a time period (Today=1, Week=2, Month=3, Year=4). Only accessible
        by authenticated users with valid tenant permissions and active SOAR integration.

        Query Parameters:
            filter_type (int): 1=Today, 2=Week, 3=Month, 4=Year (default: 3)

        Returns:
            Dictionary with two lists: 'open' (status='1') and 'closed' (status='2')
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

            # Step 4: Get filter_type from query params (default to MONTH)
            filter_type_param = request.query_params.get("filter_type", "3")
            try:
                filter_type_value = int(filter_type_param)
                filter_type = FilterType(filter_type_value)
            except (ValueError, KeyError):
                return Response(
                    {
                        "error": "Invalid filter_type. Use 1 (Today), 2 (Week), 3 (Month), or 4 (Year)."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Step 5: Determine date filter
            now = timezone.now()
            if filter_type == FilterType.TODAY:
                start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
            elif filter_type == FilterType.WEEK:
                start_date = now - timedelta(days=7)
            elif filter_type == FilterType.MONTH:
                start_date = now - timedelta(days=30)
            elif filter_type == FilterType.YEAR:
                start_date = now - timedelta(days=365)

            # Step 6: Query for incidents with status='1' (Open)
            open_incidents = DUCortexSOARIncidentFinalModel.objects.filter(
                status="1", cortex_soar_tenant_id__in=soar_ids, created__gte=start_date
            ).order_by("-created")[:5]

            # Step 7: Query for incidents with status='2' (Closed)
            closed_incidents = DUCortexSOARIncidentFinalModel.objects.filter(
                status="2", cortex_soar_tenant_id__in=soar_ids, created__gte=start_date
            ).order_by("-created")[:5]

            # Step 8: Serialize both sets of incidents
            open_serializer = RecentIncidentsSerializer(open_incidents, many=True)
            closed_serializer = RecentIncidentsSerializer(closed_incidents, many=True)

            # Step 9: Return response with two lists
            return Response(
                {"open": open_serializer.data, "closed": closed_serializer.data},
                status=status.HTTP_200_OK,
            )
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
        - True positive logic (ready incidents with proper fields)
        - optional filter_type (1–4) using created column
        - optional incident_priority (P1, P2, P3, P4)

        Query Parameters:
            filter_type (int): 1=Today, 2=Week, 3=Month, 4=Year
            priority (int): 1=P4 Low, 2=P3 Medium, 3=P2 High, 4=P1 Critical

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

            # Step 2: Apply true positive logic filters
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

            # Step 3: Handle filter_type using created column
            filter_type = request.query_params.get("filter_type")
            if filter_type:
                try:
                    filter_enum = FilterType(int(filter_type))
                    now = timezone.now()
                    if filter_enum == FilterType.TODAY:
                        start_date = now.replace(
                            hour=0, minute=0, second=0, microsecond=0
                        )
                    elif filter_enum == FilterType.WEEK:
                        start_date = now - timedelta(days=7)
                    elif filter_enum == FilterType.MONTH:
                        start_date = now - timedelta(days=30)
                    elif filter_enum == FilterType.YEAR:
                        start_date = now - timedelta(days=365)
                    filters &= Q(created__gte=start_date)
                except Exception:
                    return Response(
                        {
                            "error": "Invalid filter_type. Use 1=Today, 2=Week, 3=Month, 4=Year."
                        },
                        status=400,
                    )

            # Step 4: Handle incident_priority filter using SlaLevelChoices values
            priority = request.query_params.get("priority")
            if priority:
                try:
                    priority_int = int(priority)
                    # Map to SlaLevelChoices: 1=P4, 2=P3, 3=P2, 4=P1
                    if priority_int not in [1, 2, 3, 4]:
                        raise ValueError

                    # Map integer to priority string for filtering
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

            # Step 5: Apply filters
            incidents_qs = DUCortexSOARIncidentFinalModel.objects.filter(filters)

            # Step 6: Prepare summary counts based on incident_priority
            priority_counts = incidents_qs.values("incident_priority").annotate(
                count=Count("incident_priority")
            )

            # Initialize summary with priority labels set to 0
            summary = {"P1 Critical": 0, "P2 High": 0, "P3 Medium": 0, "P4 Low": 0}

            # Update counts for priorities present in the data
            for item in priority_counts:
                priority_value = item["incident_priority"]
                if priority_value:
                    # Map priority strings to summary labels
                    if "P1" in priority_value:
                        summary["P1 Critical"] = item["count"]
                    elif "P2" in priority_value:
                        summary["P2 High"] = item["count"]
                    elif "P3" in priority_value:
                        summary["P3 Medium"] = item["count"]
                    elif "P4" in priority_value:
                        summary["P4 Low"] = item["count"]

            # Step 7: Limit to top 10 incidents
            incidents = incidents_qs.order_by("-created")[:10]

            # Step 8: Serialize and return response
            serializer = RecentIncidentsSerializer(incidents, many=True)
            return Response({"data": serializer.data, "summary": summary}, status=200)

        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)
        except Exception as e:
            logger.error("Error in AllIncidentsView: %s", str(e))
            return Response({"error": str(e)}, status=500)


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

            # Handle filter_type (same as AllIncidentsView)
            filter_type = request.query_params.get("filter_type")
            if filter_type:
                try:
                    filter_enum = FilterType(int(filter_type))
                    now = timezone.now()
                    if filter_enum == FilterType.TODAY:
                        start_date = now.replace(
                            hour=0, minute=0, second=0, microsecond=0
                        )
                    elif filter_enum == FilterType.WEEK:
                        start_date = now - timedelta(days=7)
                    elif filter_enum == FilterType.MONTH:
                        start_date = now - timedelta(days=30)
                    elif filter_enum == FilterType.YEAR:
                        start_date = now - timedelta(days=365)
                    filters &= Q(created__gte=start_date)
                except Exception:
                    return Response(
                        {
                            "error": "Invalid filter_type. Use 1=Today, 2=Week, 3=Month, 4=Year."
                        },
                        status=400,
                    )

            # Handle severity
            severity = request.query_params.get("severity")
            if severity is not None:
                try:
                    severity_int = int(severity)
                    if severity_int not in range(0, 7):
                        raise ValueError
                    filters &= Q(severity=severity_int)
                except ValueError:
                    return Response(
                        {"error": "Invalid severity. Must be between 0 and 6."},
                        status=400,
                    )

            # Handle priority (using SlaLevelChoices)
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
            severity_counts = incidents_qs.values("severity").annotate(
                count=Count("severity")
            )

            # Initialize severity summary with all severity labels set to 0
            severity_summary = {label: 0 for label in SEVERITY_LABELS.values()}

            # Update counts for severities present in the data
            for item in severity_counts:
                severity_value = item["severity"]
                label = SEVERITY_LABELS.get(
                    severity_value, f"Unknown ({severity_value})"
                )
                severity_summary[label] = item["count"]

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
                {"summary": severity_summary, "priority_summary": priority_summary},
                status=200,
            )

        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)
        except Exception as e:
            logger.error("Error in IncidentSummaryView: %s", str(e))
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
                elif filter_type_enum == FilterType.QUARTER:
                    start_date = today - timedelta(days=89)
                    end_date = today
                elif filter_type_enum == FilterType.YEAR:
                    start_date = today - timedelta(days=364)
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


# class SLAComplianceView(APIView):
#     authentication_classes = [JWTAuthentication]
#     permission_classes = [IsTenant]

#     def get(self, request):
#         try:
#             tenant = Tenant.objects.get(tenant=request.user)
#             logger.info(f"SLAComplianceView | Authenticated Tenant ID: {tenant.id}")
#         except Tenant.DoesNotExist:
#             return Response({"error": "Tenant not found."}, status=404)

#         try:
#             soar_integrations = tenant.company.integrations.filter(
#                 integration_type=IntegrationTypes.SOAR_INTEGRATION,
#                 soar_subtype=SoarSubTypes.CORTEX_SOAR,
#                 status=True,
#             )
#             if not soar_integrations.exists():
#                 return Response(
#                     {"error": "No active SOAR integration configured."}, status=400
#                 )

#             soar_tenants = tenant.company.soar_tenants.all()
#             if not soar_tenants:
#                 return Response({"error": "No SOAR tenants found."}, status=404)
#             soar_ids = [t.id for t in soar_tenants]

#             filters = Q(cortex_soar_tenant_id__in=soar_ids)

#             incidents = DUCortexSOARIncidentFinalModel.objects.filter(
#                 filters,
#                 incident_tta__isnull=False,
#                 incident_ttn__isnull=False,
#                 incident_ttdn__isnull=False,
#             )

#             if tenant.company.is_default_sla:
#                 sla_metrics = DefaultSoarSlaMetric.objects.all()
#             else:
#                 sla_metrics = SoarTenantSlaMetric.objects.filter(
#                     soar_tenant__in=soar_tenants, company=tenant.company
#                 )

#             sla_metrics_dict = {metric.sla_level: metric for metric in sla_metrics}

#             priority_map = {
#                 "P1 Critical": SlaLevelChoices.P1,
#                 "P2 High": SlaLevelChoices.P2,
#                 "P3 Medium": SlaLevelChoices.P3,
#                 "P4 Low": SlaLevelChoices.P4,
#             }

#             met_sla_count = 0
#             breached_sla_count = 0
#             total_incident_count = 0

#             for incident in incidents:
#                 sla_level = priority_map.get(incident.incident_priority)
#                 if not sla_level:
#                     continue

#                 sla_metric = sla_metrics_dict.get(sla_level)
#                 if not sla_metric:
#                     continue

#                 total_incident_count += 1
#                 created = incident.created
#                 any_breach = False

#                 if incident.incident_tta:
#                     tta_minutes = (incident.incident_tta - created).total_seconds() / 60
#                     if tta_minutes > sla_metric.tta_minutes:
#                         any_breach = True

#                 if incident.incident_ttn:
#                     ttn_minutes = (incident.incident_ttn - created).total_seconds() / 60
#                     if ttn_minutes > sla_metric.ttn_minutes:
#                         any_breach = True

#                 if incident.incident_ttdn:
#                     ttdn_minutes = (
#                         incident.incident_ttdn - created
#                     ).total_seconds() / 60
#                     if ttdn_minutes > sla_metric.ttdn_minutes:
#                         any_breach = True

#                 if any_breach:
#                     breached_sla_count += 1
#                 else:
#                     met_sla_count += 1

#             incident_met_percentage = (
#                 round((met_sla_count / total_incident_count) * 100, 2)
#                 if total_incident_count > 0
#                 else 0.0
#             )
#             total_breach_incident_percentage = (
#                 round((breached_sla_count / total_incident_count) * 100, 2)
#                 if total_incident_count > 0
#                 else 0.0
#             )

#             return Response(
#                 {
#                     "total_breached_incidents": breached_sla_count,
#                     "total_met_target_incidents": met_sla_count,
#                     "overall_compliance_percentage": incident_met_percentage,
#                     "incident_met_percentage": incident_met_percentage,
#                     "total_breach_incident_percentage": total_breach_incident_percentage,
#                 }
#             )

#         except Exception as e:
#             logger.error(f"SLAComplianceView Error: {str(e)}")
#             return Response({"error": str(e)}, status=500)


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
            logger.debug("Tenant ID: %s, User ID: %s", tenant.id, request.user.id)
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)

        try:
            soar_tenants = tenant.company.soar_tenants.all()
            if not soar_tenants:
                return Response({"error": "No SOAR tenants found."}, status=404)
            soar_ids = [t.id for t in soar_tenants]

            # FIXED: Use consistent filtering logic with DashboardView
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

            # Total incidents = True Positives + False Positives (matches DashboardView)
            base_filters = true_positive_filters | false_positive_filters

            # Date filtering logic (applied on top of base filters)
            filter_type = request.query_params.get("filter_type")
            start_date = request.query_params.get("start_date")
            end_date = request.query_params.get("end_date")
            db_timezone = timezone.get_fixed_timezone(240)
            now = timezone.now().astimezone(db_timezone)

            # Start with base filters
            filters = base_filters

            if start_date and end_date:
                try:
                    start_date = timezone.make_aware(
                        datetime.strptime(start_date, "%Y-%m-%d"), timezone=db_timezone
                    )
                    end_date = timezone.make_aware(
                        datetime.strptime(end_date, "%Y-%m-%d")
                        + timedelta(days=1)
                        - timedelta(microseconds=1),
                        timezone=db_timezone,
                    )
                    filters &= Q(created__range=[start_date, end_date])
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
                        end_date = now
                        filters &= Q(created__range=[start_date, end_date])
                    elif filter_type == FilterType.WEEK:
                        start_date = now - timedelta(days=now.weekday())
                        start_date = start_date.replace(
                            hour=0, minute=0, second=0, microsecond=0
                        )
                        end_date = now
                        filters &= Q(created__range=[start_date, end_date])
                    elif filter_type == FilterType.MONTH:
                        start_date = now.replace(
                            day=1, hour=0, minute=0, second=0, microsecond=0
                        )
                        end_date = now
                        filters &= Q(created__range=[start_date, end_date])
                    elif filter_type == FilterType.QUARTER:
                        current_quarter = (now.month - 1) // 3 + 1
                        quarter_start_month = 3 * current_quarter - 2
                        start_date = now.replace(
                            month=quarter_start_month,
                            day=1,
                            hour=0,
                            minute=0,
                            second=0,
                            microsecond=0,
                        )
                        end_date = now
                        filters &= Q(created__range=[start_date, end_date])
                    elif filter_type == FilterType.YEAR:
                        start_date = now.replace(
                            month=1, day=1, hour=0, minute=0, second=0, microsecond=0
                        )
                        end_date = now
                        filters &= Q(created__range=[start_date, end_date])
                except Exception:
                    return Response({"error": "Invalid filter_type."}, status=400)

            # FIXED: Apply the consistent filters (no need for additional field checks)
            # The base filters already ensure these fields are not null for true positives
            incidents = DUCortexSOARIncidentFinalModel.objects.filter(filters)

            if tenant.company.is_default_sla:
                sla_metrics = DefaultSoarSlaMetric.objects.all()
            else:
                sla_metrics = SoarTenantSlaMetric.objects.filter(
                    soar_tenant__in=soar_tenants, company=tenant.company
                )
            sla_metrics_dict = {metric.sla_level: metric for metric in sla_metrics}

            # FIXED: Use exact same priority mapping as SLASeverityMetricsView
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

                # FIXED: Add null checks for safety (even though base filters should handle this)
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
                    "tta_breached_incidents_list": [],  # Add list for breached incidents
                    "ttn_breached_incidents_list": [],  # Add list for breached incidents
                    "ttdn_breached_incidents_list": [],  # Add list for breached incidents
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
                    response_data[level.label]["tta_breached_incidents_list"].append(
                        {"db_id": inc.db_id, "id": inc.id}
                    )

                # Calculate TTN metrics
                ttn_delta = (inc.incident_ttn - occured).total_seconds() / 60
                if ttn_delta <= sla.ttn_minutes:
                    response_data[level.label]["ttn_successful_incidents"] += 1
                else:
                    response_data[level.label]["ttn_breached_incidents"] += 1
                    response_data[level.label]["ttn_breached_incidents_list"].append(
                        {"db_id": inc.db_id, "id": inc.id}
                    )

                # Calculate TTDN metrics
                ttdn_delta = (inc.incident_ttdn - occured).total_seconds() / 60
                if ttdn_delta <= sla.ttdn_minutes:
                    response_data[level.label]["ttdn_successful_incidents"] += 1
                else:
                    response_data[level.label]["ttdn_breached_incidents"] += 1
                    response_data[level.label]["ttdn_breached_incidents_list"].append(
                        {"db_id": inc.db_id, "id": inc.id}
                    )

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
            start_date_str = request.query_params.get("start_date")
            end_date_str = request.query_params.get("end_date")
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

            # Step 7: Apply date filters with validation (same as original)
            start_date = None
            end_date = None
            occurred_start = None
            occurred_end = None

            if start_date_str:
                try:
                    start_date = make_aware(
                        datetime.strptime(start_date_str, date_format)
                    ).date()
                    filters &= Q(created__date__gte=start_date)
                except ValueError:
                    return Response(
                        {"error": "Invalid start_date format. Use YYYY-MM-DD."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if end_date_str:
                try:
                    end_date = make_aware(
                        datetime.strptime(end_date_str, date_format)
                    ).date()
                    filters &= Q(created__date__lte=end_date)
                except ValueError:
                    return Response(
                        {"error": "Invalid end_date format. Use YYYY-MM-DD."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

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

            # Validate date ranges
            if start_date and end_date and start_date > end_date:
                return Response(
                    {"error": "start_date cannot be greater than end_date."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

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
                    "actual_minutes": actual_minutes,
                    "breach_duration_minutes": breach_duration,
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
            elif filter_type == FilterType.YEAR.value:
                date_threshold = now - timedelta(days=365)
                comparison_period = now - timedelta(days=730)
                period_name = "last year"
            elif filter_type == FilterType.QUARTER.value:
                date_threshold = now - timedelta(weeks=13)
                comparison_period = now - timedelta(weeks=26)
                period_name = "last quarter"
            elif filter_type == FilterType.LAST_6_MONTHS.value:
                date_threshold = now - timedelta(days=180)
                comparison_period = now - timedelta(days=360)
                period_name = "last 6 months"
            elif filter_type == FilterType.LAST_3_WEEKS.value:
                date_threshold = now - timedelta(weeks=3)
                comparison_period = now - timedelta(weeks=6)
                period_name = "last 3 weeks"
            elif filter_type == FilterType.LAST_MONTH.value:
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
            elif filter_type in [FilterType.WEEK.value, FilterType.LAST_3_WEEKS.value]:
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
                FilterType.LAST_MONTH.value,
                FilterType.QUARTER.value,
                FilterType.LAST_6_MONTHS.value,
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
            elif filter_type == FilterType.YEAR.value:
                start_time = date_threshold
                end_time = now
                current_time = start_time
                while current_time <= end_time:
                    next_time = (
                        current_time.replace(day=1) + timedelta(days=32)
                    ).replace(day=1)
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
            correlated_event_count = (
                CorrelatedEventLog.objects.filter(log_filters).aggregate(
                    total=Sum("correlated_events_count")
                )["total"]
                or 0
            )
            daily_event_counts = (
                DailyEventLog.objects.filter(log_filters)
                .order_by("date")
                .values("date", "daily_count")
            )
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
            monthly_avg_eps = (
                MonthlyAvgEpsLog.objects.filter(log_filters).aggregate(
                    total=Sum("monthly_avg_eps")
                )["total"]
                or 0
            )
            last_month_avg_eps = (
                LastMonthAvgEpsLog.objects.filter(log_filters).aggregate(
                    total=Sum("last_month_avg_eps")
                )["total"]
                or 0
            )
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
            total_traffic = (
                TotalTrafficLog.objects.filter(log_filters).aggregate(
                    total=Sum("total_traffic")
                )["total"]
                or 0
            )
            destination_addresses = (
                DestinationAddressLog.objects.filter(log_filters)
                .order_by("-address_count")[:10]
                .values("destination_address", "address_count")
            )
            top_destination_connections = (
                TopDestinationConnectionLog.objects.filter(log_filters)
                .order_by("-connection_count")[:5]
                .values("destination_address", "connection_count")
            )
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
