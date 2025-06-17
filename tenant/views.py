import json
import time
from collections import Counter
from datetime import datetime, timedelta

from django.db.models import (
    Case,
    Count,
    ExpressionWrapper,
    F,
    FloatField,
    IntegerField,
    Q,
    When,
)
from django.db.models.functions import ExtractSecond
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
from common.constants import PaginationConstants
from integration.models import (
    IntegrationTypes,
    ItsmSubTypes,
    SiemSubTypes,
    SoarSubTypes,
)
from tenant.models import (
    Alert,
    DUCortexSOARIncidentFinalModel,
    DuCortexSOARTenants,
    DuIbmQradarTenants,
    DuITSMFinalTickets,
    DuITSMTenants,
    IBMQradarAssests,
    IBMQradarEPS,
    IBMQradarEventCollector,
    IBMQradarOffense,
    Tenant,
    TenantPermissionChoices,
    TenantQradarMapping,
    TenantRole,
    ThreatIntelligenceTenant,
    ThreatIntelligenceTenantAlerts,
)
from tenant.serializers import (
    AlertSerializer,
    DUCortexSOARIncidentSerializer,
    DuCortexSOARTenantsSerializer,
    DuIbmQradarTenantsSerializer,
    DuITSMTenantsSerializer,
    DuITSMTicketsSerializer,
    IBMQradarAssestsSerializer,
    IBMQradarEPSSerializer,
    IBMQradarEventCollectorSerializer,
    TenantRoleSerializer,
)
from tenant.threat_intelligence_tasks import sync_threat_alert_details


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
        # sync_threat_intel.delay()
        # sync_threat_intel_for_tenants.delay()
        sync_threat_alert_details.delay()
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
        try:
            # Step 1: Get current tenant
            tenant = Tenant.objects.select_related("tenant").get(tenant=request.user)

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
            # Step 2: Get mapped collector IDs
            collector_ids = (
                TenantQradarMapping.objects.filter(tenant=tenant)
                .prefetch_related("event_collectors")
                .values_list("event_collectors__id", flat=True)
            )

            if not collector_ids:
                return Response(
                    {"detail": "No Event Collectors mapped to this tenant."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Step 3: Parse date filters
            start_date_str = request.query_params.get("start_date")
            end_date_str = request.query_params.get("end_date")
            start_date = parse_date(start_date_str) if start_date_str else None
            end_date = parse_date(end_date_str) if end_date_str else None

            if start_date and end_date and start_date > end_date:
                return Response(
                    {"error": "start_date cannot be greater than end_date."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Step 4: Filter assets
            filters = Q(event_collector_id__in=collector_ids)
            if start_date:
                filters &= Q(creation_date_converted__gte=start_date)
            if end_date:
                filters &= Q(creation_date_converted__lte=end_date)

            assets = (
                IBMQradarAssests.objects.filter(filters)
                .select_related("event_collector", "log_source_type")
                .order_by("-creation_date_converted")
            )

            # Step 5: Pagination
            paginator = PageNumberPagination()
            paginator.page_size = PaginationConstants.PAGE_SIZE
            result_page = paginator.paginate_queryset(assets, request)

            # Step 6: Serialization
            serializer = IBMQradarAssestsSerializer(result_page, many=True)
            return paginator.get_paginated_response(serializer.data)

        except Tenant.DoesNotExist:
            return Response(
                {"detail": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
            )


# class TenantITSMTicketsView(APIView):
#     authentication_classes = [JWTAuthentication]
#     permission_classes = [IsTenant]

#     def get(self, request):
#         try:
#             tenant = Tenant.objects.get(tenant=request.user)
#         except Tenant.DoesNotExist:
#             return Response(
#                 {"error": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
#             )

#         itsm_integrations = tenant.integrations.filter(
#             integration_type=IntegrationTypes.ITSM_INTEGRATION,
#             itsm_subtype=ItsmSubTypes.MANAGE_ENGINE,
#             status=True,
#         )
#         if not itsm_integrations.exists():
#             return Response(
#                 {"error": "No active ITSM integration configured for tenant."},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )
#         itsm_tenant_ids = tenant.itsm_tenants.values_list("id", flat=True)

#         tickets = DuITSMFinalTickets.objects.filter(itsm_tenant__in=itsm_tenant_ids)

#         # Parse start_date and end_date from query params
#         start_date_str = request.query_params.get("start_date")
#         end_date_str = request.query_params.get("end_date")

#         date_format_in_db = "%b %d, %Y %I:%M %p"  # e.g., "Apr 17, 2025 10:42 PM"
#         date_format_filter = "%Y-%m-%d"  # e.g., "2025-04-17"

#         def parse_ticket_date(ticket):
#             try:
#                 return datetime.strptime(ticket.creation_date, date_format_in_db).date()
#             except Exception:
#                 return None

#         if start_date_str:
#             try:
#                 start_date = datetime.strptime(
#                     start_date_str, date_format_filter
#                 ).date()
#                 tickets = [
#                     t
#                     for t in tickets
#                     if (dt := parse_ticket_date(t)) and dt >= start_date
#                 ]
#             except ValueError:
#                 return Response(
#                     {"error": "Invalid start_date format. Use YYYY-MM-DD."}, status=400
#                 )

#         if end_date_str:
#             try:
#                 end_date = datetime.strptime(end_date_str, date_format_filter).date()
#                 tickets = [
#                     t
#                     for t in tickets
#                     if (dt := parse_ticket_date(t)) and dt <= end_date
#                 ]
#             except ValueError:
#                 return Response(
#                     {"error": "Invalid end_date format. Use YYYY-MM-DD."}, status=400
#                 )
#             tickets.sort(key=lambda t: parse_ticket_date(t) or datetime.min.date())
#         else:
#             # No filtering needed, just order in queryset
#             tickets = list(tickets)
#             tickets.sort(
#                 key=lambda t: parse_ticket_date(t) or datetime.min.date(), reverse=True
#             )
#             # tickets = tickets.order_by("creation_date")
#         # tickets.sort(key=lambda t: parse_ticket_date(t) or datetime.min.date())
#         # Pagination
#         paginator = PageNumberPagination()
#         paginator.page_size = PaginationConstants.PAGE_SIZE
#         paginated_tickets = paginator.paginate_queryset(tickets, request)


#         serializer = DuITSMTicketsSerializer(paginated_tickets, many=True)
#         return paginator.get_paginated_response(serializer.data)
class TenantITSMTicketsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        try:
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response(
                {"error": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
            )

        itsm_integrations = tenant.integrations.filter(
            integration_type=IntegrationTypes.ITSM_INTEGRATION,
            itsm_subtype=ItsmSubTypes.MANAGE_ENGINE,
            status=True,
        )
        if not itsm_integrations.exists():
            return Response(
                {"error": "No active ITSM integration configured for tenant."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        itsm_tenant_ids = tenant.itsm_tenants.values_list("id", flat=True)

        tickets = DuITSMFinalTickets.objects.filter(itsm_tenant__in=itsm_tenant_ids)

        # Parse query parameters for filters
        start_date_str = request.query_params.get("start_date")
        end_date_str = request.query_params.get("end_date")
        id_filter = request.query_params.get("id")
        name_filter = request.query_params.get("name")
        subject_filter = request.query_params.get("subject")
        status_filter = request.query_params.get("status")
        created_by_filter = request.query_params.get("created_by")

        date_format_in_db = "%b %d, %Y %I:%M %p"  # e.g., "Apr 17, 2025 10:42 PM"
        date_format_filter = "%Y-%m-%d"  # e.g., "2025-04-17"

        def parse_ticket_date(ticket):
            try:
                return datetime.strptime(ticket.creation_date, date_format_in_db).date()
            except Exception:
                return None

        # Convert tickets to a list for in-memory filtering
        tickets = list(tickets)

        # Apply filters
        if id_filter:
            try:
                id_value = int(id_filter)
                tickets = [t for t in tickets if t.id == id_value]
            except ValueError:
                return Response(
                    {"error": "Invalid id format. Must be an integer."}, status=400
                )

        if name_filter:
            tickets = [
                t for t in tickets if name_filter.lower() in t.account_name.lower()
            ]

        if subject_filter:
            tickets = [
                t for t in tickets if subject_filter.lower() in t.subject.lower()
            ]

        if status_filter:
            tickets = [t for t in tickets if status_filter.lower() == t.status.lower()]

        if created_by_filter:
            tickets = [
                t
                for t in tickets
                if created_by_filter.lower() in t.created_by_name.lower()
            ]

        if start_date_str:
            try:
                start_date = datetime.strptime(
                    start_date_str, date_format_filter
                ).date()
                tickets = [
                    t
                    for t in tickets
                    if (dt := parse_ticket_date(t)) and dt >= start_date
                ]
            except ValueError:
                return Response(
                    {"error": "Invalid start_date format. Use YYYY-MM-DD."}, status=400
                )

        if end_date_str:
            try:
                end_date = datetime.strptime(end_date_str, date_format_filter).date()
                tickets = [
                    t
                    for t in tickets
                    if (dt := parse_ticket_date(t)) and dt <= end_date
                ]
            except ValueError:
                return Response(
                    {"error": "Invalid end_date format. Use YYYY-MM-DD."}, status=400
                )

        # Sort tickets by creation_date (descending)
        tickets.sort(
            key=lambda t: parse_ticket_date(t) or datetime.min.date(), reverse=True
        )

        # Pagination
        paginator = PageNumberPagination()
        paginator.page_size = PaginationConstants.PAGE_SIZE
        paginated_tickets = paginator.paginate_queryset(tickets, request)

        serializer = DuITSMTicketsSerializer(paginated_tickets, many=True)
        return paginator.get_paginated_response(serializer.data)


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
        if not soar_tenants:
            return Response({"error": "No SOAR tenants found."}, status=404)

        soar_ids = [t.id for t in soar_tenants]

        filter_type = request.query_params.get("filter", "all")
        start_date_str = request.query_params.get("start_date")
        end_date_str = request.query_params.get("end_date")

        try:
            queryset = DUCortexSOARIncidentFinalModel.objects.filter(
                cortex_soar_tenant__in=soar_ids
            )

            # Apply date range filter with validation
            start_date = None
            end_date = None
            date_format = "%Y-%m-%d"
            if start_date_str:
                try:
                    start_date = make_aware(
                        datetime.strptime(start_date_str, date_format)
                    ).date()
                except ValueError:
                    return Response(
                        {"error": "Invalid start_date format. Use YYYY-MM-DD."},
                        status=400,
                    )

            if end_date_str:
                try:
                    end_date = make_aware(
                        datetime.strptime(end_date_str, date_format)
                    ).date()  # + timedelta(days=1)
                except ValueError:
                    return Response(
                        {"error": "Invalid end_date format. Use YYYY-MM-DD."},
                        status=400,
                    )

            if start_date and end_date and start_date > end_date:
                return Response(
                    {"error": "start_date cannot be greater than end_date."}, status=400
                )

            if start_date:
                queryset = queryset.filter(created__date__gte=start_date)

            if end_date:
                queryset = queryset.filter(created__date__lte=end_date)

            if filter_type != "all":
                if filter_type == "unassigned":
                    queryset = queryset.filter(owner__isnull=True)
                elif filter_type == "pending":
                    queryset = queryset.filter(status="Pending")
                elif filter_type == "false-positive":
                    queryset = queryset.filter(status="False Positive")
                elif filter_type == "closed":
                    queryset = queryset.filter(status="Closed")
                elif filter_type == "error":
                    queryset = queryset.filter(status="Error")

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

            incidents = []
            # severity_map = {1: "P1", 2: "P2", 3: "P3", 4: "P4"}
            for row in queryset:
                # priority = row["incident_priority"] or severity_map.get(
                #     row["severity"], "P4"
                # )
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

                incidents.append(
                    {
                        "id": f"{row['id']}",
                        "db_id": row["db_id"],
                        "account": row["account"],
                        "name": row["name"],
                        "description": row["name"].strip().split(" ", 1)[1],
                        "status": row["status"],
                        "severity": row["severity"],
                        "priority": row["incident_priority"],
                        "phase": row["incident_phase"],
                        # "priority": priority,
                        "created": created_date,
                        "assignee": row["owner"],
                        "playbook": row["playbook_id"],
                        "occurred": occurred_date,
                        "sla": row["sla"],
                    }
                )

            return Response({"incidents": incidents}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error("Error in IncidentsView: %s", str(e))
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# class IncidentsView(APIView):
#     authentication_classes = [JWTAuthentication]
#     permission_classes = [IsTenant]

#     def get(self, request):
#         try:
#             tenant = Tenant.objects.get(tenant=request.user)
#         except Tenant.DoesNotExist:
#             return Response({"error": "Tenant not found."}, status=404)

#         soar_tenants = tenant.soar_tenants.all()
#         if not soar_tenants:
#             return Response({"error": "No SOAR tenants found."}, status=404)

#         soar_ids = [t.id for t in soar_tenants]

#         if not soar_ids:
#             return Response({"error": "No SOAR tenants found."}, status=404)

#         # Get filter_type from query parameter, default to 'all'
#         filter_type = request.query_params.get("filter", "all")

#         try:
#             # Base queryset
#             queryset = DUCortexSOARIncidentFinalModel.objects.filter(
#                 cortex_soar_tenant__in=soar_ids
#             ).values(
#                 "id",
#                 "db_id",
#                 "account",
#                 "name",
#                 "status",
#                 "severity",
#                 "incident_priority",
#                 "created",
#                 "owner",
#                 "playbook_id",
#                 "occured",
#                 "sla",
#             )

#             # Apply filters
#             if filter_type != "all":
#                 if filter_type == "unassigned":
#                     queryset = queryset.filter(owner__isnull=True)
#                 elif filter_type == "pending":
#                     queryset = queryset.filter(status="Pending")
#                 elif filter_type == "false-positive":
#                     queryset = queryset.filter(status="False Positive")
#                 elif filter_type == "closed":
#                     queryset = queryset.filter(status="Closed")
#                 elif filter_type == "error":
#                     queryset = queryset.filter(status="Error")

#             # Order by created DESC
#             queryset = queryset.order_by("-created")

#             # Transform data
#             incidents = []
#             severity_map = {1: "P1", 2: "P2", 3: "P3", 4: "P4"}
#             for row in queryset:
#                 # Determine priority
#                 priority = row["incident_priority"] or severity_map.get(
#                     row["severity"], "P4"
#                 )

#                 # Format dates
#                 created_date = (
#                     row["created"].strftime("%Y-%m-%d %I:%M %p")
#                     if row["created"]
#                     else "N/A"
#                 )
#                 occurred_date = (
#                     row["occured"].strftime("%Y-%m-%d %I:%M %p")
#                     if row["occured"]
#                     else "N/A"
#                 )

#                 incidents.append(
#                     {
#                         "id": f"{row['id']}",
#                         "db_id": row["db_id"],
#                         "account": row["account"],
#                         "name": row["name"],
#                         "status": row["status"],
#                         "priority": priority,
#                         "created": created_date,
#                         "assignee": row["owner"],
#                         "playbook": row["playbook_id"],
#                         "occurred": occurred_date,
#                         "sla": row["sla"],
#                     }
#                 )

#             return Response({"incidents": incidents}, status=status.HTTP_200_OK)

#         except Exception as e:
#             logger.error("Error in IncidentsView: %s", str(e))
#             return Response(
#                 {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )


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

        # Step 3: Get SOAR tenant IDs
        soar_tenants = tenant.soar_tenants.all()
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
            filters &= Q(name__icontains=description_filter)  # Description derived from name

        if status_filter:
            filters &= Q(status__iexact=status_filter)

        if severity_filter:
            try:
                severity_value = int(severity_filter)
                filters &= Q(severity=severity_value)
            except ValueError:
                return Response(
                    {"error": "Invalid severity format. Must be an integer."}, status=400
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
                        {"error": "Invalid start_date format. Use YYYY-MM-DD."}, status=400
                    )

            if end_date_str:
                try:
                    end_date = make_aware(
                        datetime.strptime(end_date_str, date_format)
                    ).date()
                    queryset = queryset.filter(created__date__lte=end_date)
                except ValueError:
                    return Response(
                        {"error": "Invalid end_date format. Use YYYY-MM-DD."}, status=400
                    )

            if occurred_start_str:
                try:
                    occurred_start = make_aware(
                        datetime.strptime(occurred_start_str, date_format)
                    ).date()
                    queryset = queryset.filter(occured__date__gte=occurred_start)
                except ValueError:
                    return Response(
                        {"error": "Invalid occurred_start format. Use YYYY-MM-DD."}, status=400
                    )

            if occurred_end_str:
                try:
                    occurred_end = make_aware(
                        datetime.strptime(occurred_end_str, date_format)
                    ).date()
                    queryset = queryset.filter(occured__date__lte=occurred_end)
                except ValueError:
                    return Response(
                        {"error": "Invalid occurred_end format. Use YYYY-MM-DD."}, status=400
                    )

            # Step 9: Validate date ranges
            if start_date and end_date and start_date > end_date:
                return Response(
                    {"error": "start_date cannot be greater than end_date."}, status=400
                )

            if occurred_start and occurred_end and occurred_start > occurred_end:
                return Response(
                    {"error": "occurred_start cannot be greater than occurred_end."}, status=400
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
            for row in queryset:
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

            # Format source IPs and log source types
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
                    "assignee": incident["owner"],
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
                }
            }

            return Response(response, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error("Error in IncidentDetailView: %s", str(e))
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


# class OffenseDetailsByTenantAPIView(APIView):
#     authentication_classes = [JWTAuthentication]
#     permission_classes = [IsTenant]

#     def get(self, request):
#         try:
#             tenant = Tenant.objects.get(tenant=request.user)
#         except Tenant.DoesNotExist:
#             return Response({"error": "Tenant not found."}, status=404)

#         siem_integrations = tenant.integrations.filter(
#             integration_type=IntegrationTypes.SIEM_INTEGRATION,
#             siem_subtype=SiemSubTypes.IBM_QRADAR,
#             status=True,
#         )
#         if not siem_integrations.exists():
#             return Response(
#                 {"error": "No active SEIM integration configured for tenant."},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )
#         try:
#             tenant = request.user

#             # Get tenant mappings
#             mappings = TenantQradarMapping.objects.filter(
#                 tenant__tenant=tenant
#             ).values_list("event_collectors__id", "qradar_tenant__id")

#             if not mappings:
#                 return Response(
#                     {"error": "No mappings found for the tenant."},
#                     status=status.HTTP_404_NOT_FOUND,
#                 )

#             collector_ids, tenant_ids = zip(*mappings)

#             assets = IBMQradarAssests.objects.filter(
#                 event_collector__id__in=collector_ids
#             ).values_list("id", flat=True)

#             if not assets:
#                 return Response(
#                     {"error": "No assets found for the given collectors."},
#                     status=status.HTTP_404_NOT_FOUND,
#                 )

#             # Get filters from query params
#             start_date_str = request.query_params.get("start_date")
#             end_date_str = request.query_params.get("end_date")
#             status_filter = request.query_params.get("status")
#             severity_filter = request.query_params.get("severity")
#             db_id_filter = request.query_params.get("id")

#             # Base filters
#             filters = Q(assests__id__in=assets) & Q(
#                 qradar_tenant_domain__id__in=tenant_ids
#             )

#             # Parse and apply date filters
#             if start_date_str:
#                 try:
#                     start_date = parse_date(start_date_str)
#                     if start_date:
#                         filters &= Q(start_date__gte=start_date)
#                     else:
#                         raise ValueError
#                 except ValueError:
#                     return Response(
#                         {"error": "Invalid start_date format. Use YYYY-MM-DD."},
#                         status=400,
#                     )

#             if end_date_str:
#                 try:
#                     end_date = parse_date(end_date_str)
#                     if end_date:
#                         filters &= Q(start_date__lte=end_date)
#                     else:
#                         raise ValueError
#                 except ValueError:
#                     return Response(
#                         {"error": "Invalid end_date format. Use YYYY-MM-DD."},
#                         status=400,
#                     )

#             # Validate date range
#             if start_date_str and end_date_str and end_date < start_date:
#                 return Response(
#                     {"error": "end_date must be after or equal to start_date."},
#                     status=400,
#                 )

#             # Additional filters
#             if status_filter:
#                 filters &= Q(status__icontains=status_filter)

#             if severity_filter:
#                 filters &= Q(severity=severity_filter)

#             if db_id_filter:
#                 filters &= Q(db_id=db_id_filter)

#             offenses = (
#                 IBMQradarOffense.objects.filter(filters)
#                 .values(
#                     "id",
#                     "db_id",
#                     "description",
#                     "severity",
#                     "status",
#                     "start_date",
#                     "start_time",
#                 )
#                 .distinct()
#             )

#             return Response(
#                 {"offenses": list(offenses), "count": len(offenses)},
#                 status=status.HTTP_200_OK,
#             )

#         except Exception as e:
#             return Response(
#                 {"error": f"Something went wrong: {str(e)}"},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             )


class OffenseDetailsByTenantAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        try:
            tenant = Tenant.objects.get(tenant=request.user)
        except Tenant.DoesNotExist:
            return Response({"error": "Tenant not found."}, status=404)

        # Step 1: Check for active SIEM integration
        siem_integrations = tenant.integrations.filter(
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
            # Step 2: Get tenant mappings
            mappings = TenantQradarMapping.objects.filter(
                tenant=tenant  # Fixed: Use Tenant instance, not request.user
            ).values_list("event_collectors__id", "qradar_tenant__id")

            if not mappings:
                return Response(
                    {"error": "No mappings found for the tenant."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            collector_ids, tenant_ids = zip(*mappings)

            # Step 3: Get assets for collectors
            assets = IBMQradarAssests.objects.filter(
                event_collector__id__in=collector_ids
            ).values_list("id", flat=True)

            if not assets:
                return Response(
                    {"error": "No assets found for the given collectors."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Step 4: Get filters from query params
            start_date_str = request.query_params.get("start_date")
            end_date_str = request.query_params.get("end_date")
            status_filter = request.query_params.get("status")
            severity_filter = request.query_params.get("severity")
            db_id_filter = request.query_params.get("id")

            # Step 5: Base filters
            filters = Q(assests__id__in=assets) & Q(
                qradar_tenant_domain__id__in=tenant_ids
            )

            # Step 6: Parse and apply date filters
            if start_date_str:
                try:
                    start_date = parse_date(start_date_str)
                    if start_date:
                        filters &= Q(start_date__gte=start_date)
                    else:
                        raise ValueError
                except ValueError:
                    return Response(
                        {"error": "Invalid start_date format. Use YYYY-MM-DD."},
                        status=400,
                    )

            if end_date_str:
                try:
                    end_date = parse_date(end_date_str)
                    if end_date:
                        filters &= Q(start_date__lte=end_date)
                    else:
                        raise ValueError
                except ValueError:
                    return Response(
                        {"error": "Invalid end_date format. Use YYYY-MM-DD."},
                        status=400,
                    )

            # Step 7: Validate date range
            if start_date_str and end_date_str and end_date < start_date:
                return Response(
                    {"error": "end_date must be after or equal to start_date."},
                    status=400,
                )

            # Step 8: Apply additional filters
            if status_filter:
                filters &= Q(status__icontains=status_filter)

            if severity_filter:
                filters &= Q(severity=severity_filter)

            if db_id_filter:
                filters &= Q(db_id=db_id_filter)

            # Step 9: Query offenses
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

            # Step 10: Pagination
            paginator = PageNumberPagination()
            paginator.page_size = PaginationConstants.PAGE_SIZE
            paginated_offenses = paginator.paginate_queryset(offenses, request)

            # Step 11: Return paginated response
            return paginator.get_paginated_response({"offenses": list(paginated_offenses)})

        except Exception as e:
            logger.error("Error in OffenseDetailsByTenantAPIView: %s", str(e))
            return Response(
                {"error": f"Something went wrong: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
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
            # # Step 5: Format the response
            # response_data = {
            #     "offense": {
            #         "id": offense["id"],
            #         "db_id": offense["db_id"],
            #         "description": offense["description"],
            #         "severity": offense["severity"],
            #         "status": offense["status"],
            #         # "source_address_ids": offense["source_address_ids"],
            #         "start_time": offense["start_time"],
            #     },
            #     "flows": offense["flow_count"],
            #     "events": offense["event_count"],
            #     "assets": [
            #         {
            #             "id": asset["id"],
            #             "db_id": asset["db_id"],
            #             "name": asset["name"],
            #             "description": asset["description"],
            #         }
            #         for asset in offense_assets
            #     ],
            # }

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
            # Step 1: Retrieve collector IDs from TenantQradarMapping
            tenant = request.user
            mappings = TenantQradarMapping.objects.filter(
                tenant__tenant=tenant
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

        itsm_integrations = tenant.integrations.filter(
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
            tenant = request.user
            itsm_tenant_ids = Tenant.objects.filter(tenant=tenant).values_list(
                "itsm_tenants__id", flat=True
            )

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
            # Step 1: Retrieve collector IDs from TenantQradarMapping
            tenant = request.user
            qradar_tenant_ids = TenantQradarMapping.objects.filter(
                tenant__tenant=tenant
            ).values_list("qradar_tenant__id", flat=True)

            if not qradar_tenant_ids:
                return Response(
                    {"error": "No mappings found for the tenant."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            eps_entries = IBMQradarEPS.objects.filter(domain__in=qradar_tenant_ids)
            serializer = IBMQradarEPSSerializer(eps_entries, many=True)
            return Response(serializer.data, status=200)
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


# class AlertListView(APIView):
#     authentication_classes = [JWTAuthentication]
#     permission_classes = [IsTenant]

#     def get(self, request):
#         try:
#             # Get the tenant object for the logged-in user
#             tenant = Tenant.objects.get(tenant=request.user)

#             # Determine which integration(s) to use
#             if tenant.is_defualt_threat_intel:
#                 integrations = tenant.integrations.filter(
#                     integration_type=IntegrationTypes.THREAT_INTELLIGENCE
#                 )
#             else:
#                 ti = ThreatIntelligenceTenant.objects.filter(tenant=tenant).first()
#                 if not ti:
#                     return Response({"error": "No custom threat intelligence found."}, status=404)

#                 integrations = Integration.objects.filter(
#                     threat_intelligence_subtype=ti.threat_intelligence,
#                     credentials__base_url=ti.base_url
#                 )

#             alerts = Alert.objects.filter(integration__in=integrations).order_by("-published_time")
#             serialized_alerts = [
#                 {
#                     "id": alert.id,
#                     "title": alert.title,
#                     "status": alert.status,
#                     "published_time": alert.published_time,
#                 }
#                 for alert in alerts
#             ]

#             return Response({"alerts": serialized_alerts}, status=200)

#         except Tenant.DoesNotExist:
#             return Response({"error": "Tenant not found."}, status=404)
#         except Exception as e:
#             return Response({"error": str(e)}, status=500)


class AlertListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTenant]

    def get(self, request):
        user = request.user
        try:
            tenant = Tenant.objects.get(tenant=user)
        except Tenant.DoesNotExist:
            return Response(
                {"error": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND
            )

        start_date_str = request.query_params.get("start_date")
        end_date_str = request.query_params.get("end_date")

        start_date = parse_datetime(start_date_str) if start_date_str else None
        end_date = parse_datetime(end_date_str) if end_date_str else None

        if tenant.is_defualt_threat_intel:
            integrations = tenant.integrations.all()
            queryset = Alert.objects.filter(integration__in=integrations)
        else:
            ti_entry = ThreatIntelligenceTenant.objects.filter(tenants=tenant).first()
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

        if start_date:
            queryset = queryset.filter(published_time__date__gte=start_date.date())

        if end_date:
            queryset = queryset.filter(published_time__date__lte=end_date.date())

        queryset = queryset.order_by("-published_time")

        paginator = PageNumberPagination()
        paginator.page_size = 10  # Or replace with PaginationConstants.PAGE_SIZE
        paginated_qs = paginator.paginate_queryset(queryset, request)

        serializer = AlertSerializer(paginated_qs, many=True)
        return paginator.get_paginated_response(serializer.data)
