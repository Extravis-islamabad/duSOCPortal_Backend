import json
import time
from collections import Counter
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
    Q,
    Sum,
    When,
)
from django.db.models.functions import ExtractSecond, TruncDate, TruncDay, TruncHour
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime
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
    Integration,
    IntegrationCredentials,
    IntegrationTypes,
    ItsmSubTypes,
    SiemSubTypes,
    SoarSubTypes,
    ThreatIntelligenceSubTypes,
)
from tenant.itsm_tasks import sync_itsm_tickets_soar_ids
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
        # sync_ibm.delay()
        sync_itsm_tickets_soar_ids.delay()
        # sync_daily_closure_reason_counts.delay()
        # sync_dos_event_counts.delay()
        # sync_suspicious_event_counts.delay()
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
        Retrieve IBM QRadar assets filtered by:
        - Event collector IDs mapped to the tenant
        - Optional query parameters: name, id, db_id, status, log_source_type, enabled, last_event_start_date, average_eps, start_date, end_date

        Query Parameters:
            name (str): Partial match on asset name (case-insensitive)
            id (int): Exact match on asset ID
            db_id (int): Exact match on db_id
            status (str): Exact match on status (case-insensitive)
            log_source_type (str): Partial match on log source type (case-insensitive)
            enabled (bool): Exact match on enabled status (true/false)
            last_event_start_date (YYYY-MM-DD): Exact match on last event start date
            average_eps (float): Exact match on average EPS
            start_date (YYYY-MM-DD): Assets with creation_date (parsed timestamp) on or after this date
            end_date (YYYY-MM-DD): Assets with creation_date (parsed timestamp) on or before this date

        Returns:
            Paginated response with count, next, previous, and results
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

            # Step 4: Build filters
            filters = Q(event_collector_id__in=collector_ids)

            # Name filter
            name = request.query_params.get("name")
            if name:
                filters &= Q(name__icontains=name)

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
            db_id = request.query_params.get("db_id")
            if db_id:
                try:
                    db_id_value = int(db_id)
                    filters &= Q(db_id=db_id_value)
                except ValueError:
                    return Response(
                        {"error": "Invalid db_id format. Must be an integer."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Status filter
            status_filter = request.query_params.get("status")
            if status_filter:
                filters &= Q(status__iexact=status_filter)

            # Log source type filter
            log_source_type = request.query_params.get("log_source_type")
            if log_source_type:
                filters &= Q(log_source_type__name__icontains=log_source_type)

            # Enabled filter
            enabled = request.query_params.get("enabled")
            if enabled is not None:
                try:
                    enabled_value = enabled.lower() == "true"
                    filters &= Q(enabled=enabled_value)
                except ValueError:
                    return Response(
                        {"error": "Invalid enabled format. Must be true or false."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Last event start date filter
            last_event_start_date = request.query_params.get("last_event_start_date")
            if last_event_start_date:
                try:
                    last_event_date = parse_date(last_event_start_date)
                    filters &= Q(last_event_date_converted=last_event_date)
                except ValueError:
                    return Response(
                        {
                            "error": "Invalid last_event_start_date format. Use YYYY-MM-DD."
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Average EPS filter
            average_eps = request.query_params.get("average_eps")
            if average_eps:
                try:
                    eps_value = float(average_eps)
                    filters &= Q(average_eps=eps_value)
                except ValueError:
                    return Response(
                        {"error": "Invalid average_eps format. Must be a number."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Start and end date filters for creation_date (Unix timestamp)
            start_date_str = request.query_params.get("start_date")
            end_date_str = request.query_params.get("end_date")
            start_date = parse_date(start_date_str) if start_date_str else None
            end_date = parse_date(end_date_str) if end_date_str else None

            if start_date and end_date and start_date > end_date:
                return Response(
                    {"error": "start_date cannot be greater than end_date."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Fetch assets and apply date filtering manually since creation_date is a CharField
            assets = IBMQradarAssests.objects.filter(filters).select_related(
                "event_collector", "log_source_type"
            )

            if start_date or end_date:
                filtered_assets = []
                for asset in assets:
                    try:
                        # Parse creation_date (Unix timestamp in milliseconds)
                        ts = int(asset.creation_date) / 1000  # Convert to seconds
                        asset_date = datetime.utcfromtimestamp(ts).date()
                        # Check if asset_date is within the date range
                        if (not start_date or asset_date >= start_date) and (
                            not end_date or asset_date <= end_date
                        ):
                            filtered_assets.append(asset)
                    except (ValueError, TypeError) as e:
                        logger.warning(
                            f"Skipping asset {asset.id} with invalid creation_date '{asset.creation_date}': {str(e)}"
                        )
                        continue
                assets = filtered_assets

            # Step 5: Sort
            assets = sorted(
                assets,
                key=lambda x: x.creation_date_converted or datetime.min.date(),
                reverse=True,
            )

            # Step 6: Pagination
            paginator = PageNumberPagination()
            paginator.page_size = PaginationConstants.PAGE_SIZE
            result_page = paginator.paginate_queryset(assets, request)

            # Step 7: Serialization
            serializer = IBMQradarAssestsSerializer(result_page, many=True)
            return paginator.get_paginated_response(serializer.data)

        except Exception as e:
            logger.error(f"Error in GetTenantAssetsList: {str(e)}")
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

        serializer = DuITSMTicketsSerializer(ticket)
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
            # Query severity distribution using Django ORM
            severity_data = (
                DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids
                )
                .values("severity")
                .annotate(count=Count("id"))
                .order_by("severity")
                .exclude(severity__isnull=True)  # Exclude NULL severity values
            )

            # Transform data to match Flask output
            result = []
            for item in severity_data:
                severity_value = item["severity"]
                severity_label = f"P{severity_value}"  # Convert 1,2,3,4 to P1,P2,P3,P4
                result.append({"name": severity_label, "value": item["count"]})

            return Response({"severityDistribution": result}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error("Error in SeverityDistributionView: %s", str(e))
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class TypeDistributionView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        # Extract tenant_id from X-Tenant-ID header, default to 'CDC-Mey-Tabreed'
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
        # Assuming 'request.user.tenant' gives you the logged-in tenant instance

        if not soar_tenants:
            return Response({"error": "No SOAR tenants found."}, status=404)

        soar_ids = [t.id for t in soar_tenants]

        if not soar_ids:
            return Response({"error": "No SOAR tenants found."}, status=404)

        filters = request.query_params.get("filters", "")
        filter_list = (
            [f.strip() for f in filters.split(",") if f.strip()] if filters else []
        )

        try:
            # Get current date for filtering
            today = timezone.now().date()
            yesterday = (timezone.now() - timedelta(days=1)).date()
            last_week = (timezone.now() - timedelta(days=7)).date()

            dashboard_data = {}

            # Total Incidents
            if not filter_list or "totalIncidents" in filter_list:
                total_incidents = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids
                ).count()

                new_incidents = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids, created__date=today
                ).count()

                last_week_incidents = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids, created__date__gte=last_week
                ).count()

                percent_change = (
                    ((total_incidents - last_week_incidents) / last_week_incidents)
                    * 100
                    if last_week_incidents > 0
                    else 0
                )
                change_indicator = "↑" if percent_change >= 0 else "↓"
                change_text = (
                    f"{change_indicator} {abs(percent_change):.0f}% from last week"
                )

                dashboard_data["totalIncidents"] = {
                    "count": total_incidents,
                    "change": change_text,
                    "new": new_incidents,
                }

            # Unassigned Incidents
            if not filter_list or "unassigned" in filter_list:
                unassigned_count = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids, owner__isnull=True
                ).count()

                critical_unassigned = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids, owner__isnull=True, severity=1
                ).count()

                yesterday_unassigned = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids,
                    owner__isnull=True,
                    created__date=yesterday,
                ).count()

                unassigned_change = (
                    ((unassigned_count - yesterday_unassigned) / yesterday_unassigned)
                    * 100
                    if yesterday_unassigned > 0
                    else 0
                )
                unassigned_indicator = "↑" if unassigned_change >= 0 else "↓"
                unassigned_change_text = f"{unassigned_indicator} {abs(unassigned_change):.0f}% from yesterday"

                dashboard_data["unassigned"] = {
                    "count": unassigned_count,
                    "change": unassigned_change_text,
                    "critical": critical_unassigned,
                }

            # Pending Incidents
            if not filter_list or "pending" in filter_list:
                pending_count = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids, status="Pending"
                ).count()

                awaiting_count = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids,
                    status="Pending",
                    incident_phase="Awaiting Response",
                ).count()

                yesterday_pending = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids,
                    status="Pending",
                    created__date=yesterday,
                ).count()

                pending_change = (
                    ((pending_count - yesterday_pending) / yesterday_pending) * 100
                    if yesterday_pending > 0
                    else 0
                )
                pending_indicator = "↑" if pending_change >= 0 else "↓"
                pending_change_text = (
                    f"{pending_indicator} {abs(pending_change):.0f}% from yesterday"
                )

                dashboard_data["pending"] = {
                    "count": pending_count,
                    "change": pending_change_text,
                    "awaiting": awaiting_count,
                }

            # False Positives
            if not filter_list or "falsePositives" in filter_list:
                false_positive_count = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids, status="False Positive"
                ).count()

                review_count = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids,
                    status="False Positive",
                    incident_phase="Review Needed",
                ).count()

                last_week_false_positives = (
                    DUCortexSOARIncidentFinalModel.objects.filter(
                        cortex_soar_tenant__in=soar_ids,
                        status="False Positive",
                        created__date__gte=last_week,
                    ).count()
                )

                fp_change = (
                    (
                        (false_positive_count - last_week_false_positives)
                        / last_week_false_positives
                    )
                    * 100
                    if last_week_false_positives > 0
                    else 0
                )
                fp_indicator = "↑" if fp_change >= 0 else "↓"
                fp_change_text = f"{fp_indicator} {abs(fp_change):.0f}% from last week"

                dashboard_data["falsePositives"] = {
                    "count": false_positive_count,
                    "change": fp_change_text,
                    "review": review_count,
                }

            # Closed Incidents
            if not filter_list or "closed" in filter_list:
                closed_count = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids, status="Closed", closed__date=today
                ).count()

                critical_closed = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids,
                    status="Closed",
                    severity=1,
                    closed__date=today,
                ).count()

                yesterday_closed = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids,
                    status="Closed",
                    closed__date=yesterday,
                ).count()

                closed_change = (
                    ((closed_count - yesterday_closed) / yesterday_closed) * 100
                    if yesterday_closed > 0
                    else 0
                )
                closed_indicator = "↑" if closed_change >= 0 else "↓"
                closed_change_text = (
                    f"{closed_indicator} {abs(closed_change):.0f}% from yesterday"
                )

                dashboard_data["closed"] = {
                    "count": closed_count,
                    "change": closed_change_text,
                    "critical": critical_closed,
                }

            # Error Incidents
            if not filter_list or "errors" in filter_list:
                error_count = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids, status="Error"
                ).count()

                api_error_count = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids,
                    status="Error",
                    qradar_category="API Failure",
                ).count()

                yesterday_errors = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant__in=soar_ids,
                    status="Error",
                    created__date=yesterday,
                ).count()

                error_change = error_count - yesterday_errors
                error_change_text = (
                    f"↑ {error_change} new since yesterday"
                    if error_change >= 0
                    else f"↓ {abs(error_change)} less than yesterday"
                )

                dashboard_data["errors"] = {
                    "count": error_count,
                    "change": error_change_text,
                    "api": api_error_count,
                }

            # Top Closers
            if not filter_list or "topClosers" in filter_list:
                top_closers_qs = (
                    DUCortexSOARIncidentFinalModel.objects.filter(
                        cortex_soar_tenant__in=soar_ids,
                        status="Closed",
                        closing_user_id__isnull=False,
                    )
                    .values("closing_user_id")
                    .annotate(count=Count("id"))
                    .order_by("-count")[:5]
                )

                top_closers = [
                    {"name": row["closing_user_id"], "count": row["count"]}
                    for row in top_closers_qs
                ]

                dashboard_data["topClosers"] = top_closers

            # Recent Activities
            if not filter_list or "recentActivities" in filter_list:
                recent_qs = (
                    DUCortexSOARIncidentFinalModel.objects.filter(
                        cortex_soar_tenant__in=soar_ids
                    )
                    .order_by("-modified")[:5]
                    .values("id", "name", "modified", "owner", "status")
                )

                activities = []
                for row in recent_qs:
                    time_str = row["modified"].strftime("%I:%M %p")
                    event = "Status update"
                    user = row["owner"] or "System"
                    details = f"INC-{row['id']} - {row['name']} ({row['status']})"

                    activities.append(
                        {
                            "time": time_str,
                            "event": event,
                            "user": user,
                            "details": details,
                        }
                    )

                dashboard_data["recentActivities"] = activities

            return Response(dashboard_data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error("Error in DashboardView: %s", str(e))
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


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
        filter_type = request.query_params.get("filter", "all")
        start_date_str = request.query_params.get("start_date")
        end_date_str = request.query_params.get("end_date")
        occurred_start_str = request.query_params.get("occurred_start")
        occurred_end_str = request.query_params.get("occurred_end")

        date_format = "%Y-%m-%d"  # Expected format for date inputs

        # Step 5: Initialize filters with Q object
        filters = Q(cortex_soar_tenant__in=soar_ids)

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
            filters &= Q(
                name__icontains=description_filter
            )  # Description derived from name

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

            # Step 10: Query incidents
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
                "owner",
                "playbook_id",
                "occured",
                "sla",
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

                created_date = (
                    row["created"].strftime("%Y-%m-%d %I:%M %p")
                    if row["created"]
                    else "N/A"
                )
                occurred_date = (
                    row["occured"].strftime("%Y-%m-%d %I:%M %p")
                    if row["occured"]
                    else "N/A"
                )

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
                        "assignee": row["owner"],
                        "playbook": row["playbook_id"],
                        "occurred": occurred_date,
                        "sla": row["sla"],
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

    def get(self, request, incident_id):
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
            # Fetch incident using numeric incident_id
            incident = (
                DUCortexSOARIncidentFinalModel.objects.filter(
                    id=incident_id, cortex_soar_tenant__in=soar_ids
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
                    "source_ips",
                    "log_source_type",
                    "list_of_rules_offense",
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

            # Determine priority
            # priority = incident["incident_priority"] or (
            #     {1: "P1", 2: "P2", 3: "P3", 4: "P4"}.get(incident["severity"], "P4")
            # )
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

            # Format response
            response = {
                "incident": {
                    "id": incident_id,
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
                    "creator": "System",  # No creator field in schema
                    "assignee": (
                        "N/A" if incident["owner"] == " " else incident["owner"]
                    ),
                    "description": incident["name"].strip().split(" ", 1)[1],
                    "customFields": {
                        "phase": incident["incident_phase"] or "Detection",
                        "priority": incident["incident_phase"] or None,
                        "severity": incident["severity"],
                        "sourceIPs": source_ips_str,
                        "logSourceType": log_source_type_str,
                        "category": incident["qradar_category"] or None,
                        "sub_category": incident["qradar_sub_category"] or None,
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

            # Step 3: Retrieve offenses with categories field
            offenses = IBMQradarOffense.objects.filter(
                Q(assests__id__in=assets) & Q(qradar_tenant_domain__id__in=tenant_ids)
            ).values("categories")

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
                {
                    "error": "Invalid filter value. Use 1 (TODAY), 2 (WEEK), or 3 (MONTH)."
                },
                status=400,
            )

        try:
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)

        now = timezone.now()
        if filter_enum == FilterType.TODAY:
            start_time = now.replace(hour=0, minute=0, second=0, microsecond=0)
            time_trunc = TruncHour("created_at")
        elif filter_enum == FilterType.WEEK:
            start_time = now - timedelta(days=6)
            time_trunc = TruncDay("created_at")
        elif filter_enum == FilterType.MONTH:
            start_time = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            time_trunc = TruncDate("created_at")
        else:
            return Response(
                {"error": "Invalid filter. Use 'day', 'week', or 'month'."}, status=400
            )

        # Get relevant qradar domains
        qradar_tenant_ids = tenant.company.qradar_mappings.values_list(
            "qradar_tenant__id", flat=True
        )

        # EPS data
        eps_data_raw = (
            IBMQradarEPS.objects.filter(
                domain_id__in=qradar_tenant_ids, created_at__gte=start_time
            )
            .annotate(interval=time_trunc)
            .values("interval")
            .annotate(total_eps=Sum("eps"))
            .order_by("interval")
        )

        eps_data = [
            {
                "interval": entry["interval"],
                "total_eps": float(
                    Decimal(entry["total_eps"]).quantize(
                        Decimal("0.01"), rounding=ROUND_HALF_UP
                    )
                ),
            }
            for entry in eps_data_raw
        ]
        # Get contracted volume info (we assume only one mapping per company)
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
            status=200,
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
        - optional filter_type (1–4)
        - optional severity (0–6)

        Query Parameters:
            filter_type (int): 1=Today, 2=Week, 3=Month, 4=Year
            severity (int): Severity level between 0 and 6

        Returns:
            {
                "data": [...],
                "summary": {
                    "Unknown": 0,
                    "Low": 0,
                    "Medium": 0,
                    "High": 0,
                    "Critical": 0,
                    "Major": 0,
                    "Minor": 0
                }
            }
        """
        try:
            # Step 1: Validate tenant
            tenant = Tenant.objects.get(tenant=request.user)
            soar_ids = tenant.company.soar_tenants.values_list("id", flat=True)

            if not soar_ids:
                return Response({"error": "No SOAR tenants found."}, status=404)

            # Step 2: Build filters
            filters = Q(cortex_soar_tenant__in=soar_ids)

            # Handle filter_type
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

            # Step 3: Apply filters
            incidents_qs = DUCortexSOARIncidentFinalModel.objects.filter(filters)

            # Step 4: Prepare summary counts
            severity_counts = incidents_qs.values("severity").annotate(
                count=Count("severity")
            )
            # Initialize summary with all severity labels set to 0
            summary = {label: 0 for label in SEVERITY_LABELS.values()}
            # Update counts for severities present in the data
            for item in severity_counts:
                severity_value = item["severity"]
                label = SEVERITY_LABELS.get(
                    severity_value, f"Unknown ({severity_value})"
                )
                summary[label] = item["count"]

            # Step 5: Limit to top 10 incidents
            incidents = incidents_qs.order_by("-created")[:10]

            # Step 6: Serialize and return response
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
        - optional filter_type (1–4)
        - optional severity (0–6)

        Query Parameters:
            filter_type (int): 1=Today, 2=Week, 3=Month, 4=Year
            severity (int): Severity level between 0 and 6

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
                }
            }
        """
        try:
            # Step 1: Validate tenant
            tenant = Tenant.objects.get(tenant=request.user)
            soar_ids = tenant.company.soar_tenants.values_list("id", flat=True)

            if not soar_ids:
                return Response({"error": "No SOAR tenants found."}, status=404)

            # Step 2: Build filters
            filters = Q(cortex_soar_tenant__in=soar_ids)

            # Handle filter_type
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

            # Step 3: Apply filters and calculate summary counts
            incidents_qs = DUCortexSOARIncidentFinalModel.objects.filter(filters)
            severity_counts = incidents_qs.values("severity").annotate(
                count=Count("severity")
            )

            # Initialize summary with all severity labels set to 0
            summary = {label: 0 for label in SEVERITY_LABELS.values()}

            # Update counts for severities present in the data
            for item in severity_counts:
                severity_value = item["severity"]
                label = SEVERITY_LABELS.get(
                    severity_value, f"Unknown ({severity_value})"
                )
                summary[label] = item["count"]

            # Step 4: Return summary
            return Response({"summary": summary}, status=200)

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

            filters = Q(cortex_soar_tenant_id__in=soar_ids)

            incidents = DUCortexSOARIncidentFinalModel.objects.filter(
                filters,
                incident_tta__isnull=False,
                incident_ttn__isnull=False,
                incident_ttdn__isnull=False,
            )

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
                    "total_breached_incidents": breached_sla_count,
                    "total_met_target_incidents": met_sla_count,
                    "overall_compliance_percentage": incident_met_percentage,
                    "incident_met_percentage": incident_met_percentage,
                    "total_breach_incident_percentage": total_breach_incident_percentage,
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

            filters = Q(cortex_soar_tenant_id__in=soar_ids)

            filter_type = request.query_params.get("filter_type")
            start_date = request.query_params.get("start_date")
            end_date = request.query_params.get("end_date")
            db_timezone = timezone.get_fixed_timezone(240)
            now = timezone.now().astimezone(db_timezone)

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
                        filters &= Q(created__date=now.date())
                    elif filter_type == FilterType.WEEK:
                        filters &= Q(created__gte=now - timedelta(days=7))
                    elif filter_type == FilterType.MONTH:
                        filters &= Q(created__gte=now - timedelta(days=30))
                    elif filter_type == FilterType.QUARTER:
                        filters &= Q(created__gte=now - timedelta(days=90))
                    elif filter_type == FilterType.YEAR:
                        filters &= Q(created__gte=now - timedelta(days=365))
                except Exception:
                    return Response({"error": "Invalid filter_type."}, status=400)

            incidents = DUCortexSOARIncidentFinalModel.objects.filter(
                filters,
                incident_tta__isnull=False,
                incident_ttdn__isnull=False,
                incident_ttn__isnull=False,
            )

            if tenant.company.is_default_sla:
                sla_metrics = DefaultSoarSlaMetric.objects.all()
            else:
                sla_metrics = SoarTenantSlaMetric.objects.filter(
                    soar_tenant__in=soar_tenants, company=tenant.company
                )
            sla_metrics_dict = {metric.sla_level: metric for metric in sla_metrics}

            # Map priorities to sla_level and labels
            priority_map = {
                "P1 Critical": SlaLevelChoices.P1,
                "P2 High": SlaLevelChoices.P2,
                "P3 Medium": SlaLevelChoices.P3,
                "P4 Low": SlaLevelChoices.P4,
            }
            reverse_map = {
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
                sla_level = priority_map.get(incident.incident_priority)
                if not sla_level:
                    continue

                sla_metric = sla_metrics_dict.get(sla_level)
                if not sla_metric:
                    continue

                label = reverse_map[sla_level]
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

            if tenant.company.is_default_sla:
                sla_metrics = DefaultSoarSlaMetric.objects.all()
            else:
                sla_metrics = SoarTenantSlaMetric.objects.filter(
                    soar_tenant__in=soar_tenants, company=tenant.company
                )

            sla_metrics_dict = {metric.sla_level: metric for metric in sla_metrics}

            response_list = []

            severity_levels = {
                SlaLevelChoices.P1: 4,
                SlaLevelChoices.P2: 3,
                SlaLevelChoices.P3: 2,
                SlaLevelChoices.P4: 1,
            }

            for level in severity_levels:
                sla = sla_metrics_dict.get(level)
                if not sla:
                    continue

                incidents = DUCortexSOARIncidentFinalModel.objects.filter(
                    cortex_soar_tenant_id__in=soar_ids,
                    incident_priority=SlaLevelChoices(level).label,
                    incident_tta__isnull=False,
                    incident_ttn__isnull=False,
                    incident_ttdn__isnull=False,
                )

                total = incidents.count()
                met = 0

                for inc in incidents:
                    created = inc.created
                    any_breach = False

                    if inc.incident_tta:
                        tta_delta = (inc.incident_tta - created).total_seconds() / 60
                        if tta_delta > sla.tta_minutes:
                            any_breach = True

                    if inc.incident_ttn:
                        ttn_delta = (inc.incident_ttn - created).total_seconds() / 60
                        if ttn_delta > sla.ttn_minutes:
                            any_breach = True

                    if inc.incident_ttdn:
                        ttdn_delta = (inc.incident_ttdn - created).total_seconds() / 60
                        if ttdn_delta > sla.ttdn_minutes:
                            any_breach = True

                    if not any_breach:
                        met += 1

                compliance = round((met / total) * 100, 2) if total > 0 else 0.0

                response_list.append(
                    {
                        "severity_label": SlaLevelChoices(level).label,
                        "tta_minutes": sla.tta_minutes,
                        "ttn_minutes": sla.ttn_minutes,
                        "ttdn_minutes": sla.ttdn_minutes,
                        "target_sla": f"TTA: {sla.tta_minutes} mins, TTN: {sla.ttn_minutes} mins, TTDN: {sla.ttdn_minutes} mins",
                        "compliance_percentage": compliance,
                        "status": "Fulfilled" if compliance >= 80 else "Breached",
                    }
                )

            return Response(response_list)

        except Exception as e:
            logger.error(f"Error in SLASeverityMetricsView: {str(e)}")
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

            # Build filters
            filters = Q(cortex_soar_tenant_id__in=soar_ids)

            if date_threshold:
                filters &= Q(created__gte=date_threshold)

            if priority_filter:
                try:
                    priority_value = priority_filter
                    filters &= Q(incident_priority=priority_value)
                except ValueError:
                    return Response(
                        {"error": "Invalid incident_priority format."}, status=400
                    )

            # Filter incidents
            incidents = DUCortexSOARIncidentFinalModel.objects.filter(
                filters,
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
                filters
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
                # (0, "Unknown"),
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

            # Process incident ticket details
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

                priority_incidents = incidents.filter(
                    incident_priority=reverse_priority_label.get(
                        priority_level, "Unknown"
                    ).split(" ")[0]
                )
                open_tickets = priority_incidents.filter(status=1).count()

                sla_breach_tickets = 0
                tta_times = []
                ttn_times = []
                ttdn_times = []

                for incident in priority_incidents:
                    created = incident.created
                    any_breach = False

                    if incident.incident_tta and created:
                        tta_delta = (
                            incident.incident_tta - created
                        ).total_seconds() / 60
                        tta_times.append(tta_delta)
                        if tta_delta > sla_metric.tta_minutes:
                            any_breach = True

                    if incident.incident_ttn and created:
                        ttn_delta = (
                            incident.incident_ttn - created
                        ).total_seconds() / 60
                        ttn_times.append(ttn_delta)
                        if ttn_delta > sla_metric.ttn_minutes:
                            any_breach = True

                    if incident.incident_ttdn and created:
                        ttdn_delta = (
                            incident.incident_ttdn - created
                        ).total_seconds() / 60
                        ttdn_times.append(ttdn_delta)
                        if ttdn_delta > sla_metric.ttdn_minutes:
                            any_breach = True

                    if any_breach:
                        sla_breach_tickets += 1

                avg_tta = sum(tta_times) / len(tta_times) if tta_times else 0
                avg_ttn = sum(ttn_times) / len(ttn_times) if ttn_times else 0
                avg_ttdn = sum(ttdn_times) / len(ttdn_times) if ttdn_times else 0

                incident_ticket_details.append(
                    {
                        "priority_label": priority_label,
                        "priority_level": priority_level,
                        "open_tickets": open_tickets,
                        "sla_breach_tickets": sla_breach_tickets,
                        "avg_tta_minutes": round(avg_tta, 2),
                        "avg_ttn_minutes": round(avg_ttn, 2),
                        "avg_ttdn_minutes": round(avg_ttdn, 2),
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
                filters
            ).count()
            open_counts = (
                DUCortexSOARIncidentFinalModel.objects.filter(filters, status=1)
                .values("incident_priority")
                .annotate(count=Count("id"))
            )
            closed_counts = (
                DUCortexSOARIncidentFinalModel.objects.filter(filters, status=2)
                .values("incident_priority")
                .annotate(count=Count("id"))
            )
            created_counts = (
                DUCortexSOARIncidentFinalModel.objects.filter(filters)
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

            total_eps = (
                TotalEvents.objects.aggregate(total_eps=Sum("total_events"))[
                    "total_eps"
                ]
                or 0
            )
            suspicious_activities = EventCountLog.objects.order_by("-event_count")[
                :10
            ].values("event_name", "event_count")
            recon_event_count = (
                ReconEventLog.objects.filter(created_at__gte=date_threshold).aggregate(
                    total=Sum("total_recon_events")
                )["total"]
                or 0
            )
            suspicious_event_count = (
                SuspiciousEventLog.objects.filter(
                    created_at__gte=date_threshold
                ).aggregate(total=Sum("total_suspicious_events"))["total"]
                or 0
            )
            dos_event_count = (
                DosEventLog.objects.filter(created_at__gte=date_threshold).aggregate(
                    total=Sum("total_dos_events")
                )["total"]
                or 0
            )
            top_dos_events = (
                TopDosEventLog.objects.filter(
                    # qradar_tenant__company=tenant.company,
                    created_at__gte=date_threshold
                )
                .order_by("-event_count")[:10]
                .values("event_name", "event_count")
            )
            correlated_event_count = (
                CorrelatedEventLog.objects.filter(
                    created_at__gte=date_threshold
                ).aggregate(total=Sum("correlated_events_count"))["total"]
                or 0
            )
            daily_event_counts = (
                DailyEventLog.objects.filter(created_at__gte=date_threshold)
                .order_by("date")
                .values("date", "daily_count")
            )
            top_alert_events = (
                TopAlertEventLog.objects.filter(created_at__gte=date_threshold)
                .order_by("-event_count")[:10]
                .values("alert_name", "event_count")
            )
            daily_closure_reasons = (
                DailyClosureReasonLog.objects.filter(created_at__gte=date_threshold)
                .order_by("date", "closure_reason")
                .values("date", "closure_reason", "reason_count")
            )
            monthly_avg_eps = (
                MonthlyAvgEpsLog.objects.filter(
                    created_at__gte=date_threshold
                ).aggregate(total=Sum("monthly_avg_eps"))["total"]
                or 0
            )
            last_month_avg_eps = (
                LastMonthAvgEpsLog.objects.filter(
                    created_at__gte=date_threshold
                ).aggregate(total=Sum("last_month_avg_eps"))["total"]
                or 0
            )
            weekly_avg_eps = (
                WeeklyAvgEpsLog.objects.filter(created_at__gte=date_threshold)
                .order_by("week")
                .values("week", "week_start", "weekly_avg_eps")
            )
            total_traffic = (
                TotalTrafficLog.objects.filter(
                    created_at__gte=date_threshold
                ).aggregate(total=Sum("total_traffic"))["total"]
                or 0
            )
            destination_addresses = (
                DestinationAddressLog.objects.filter(created_at__gte=date_threshold)
                .order_by("-address_count")[:10]
                .values("destination_address", "address_count")
            )
            top_destination_connections = (
                TopDestinationConnectionLog.objects.filter(
                    created_at__gte=date_threshold
                )
                .order_by("-connection_count")[:5]
                .values("destination_address", "connection_count")
            )
            daily_event_count = (
                DailyEventCountLog.objects.filter(created_at__gte=date_threshold)
                .order_by("full_date")
                .values("full_date", "daily_count")
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
