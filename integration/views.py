from loguru import logger
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from authentication.permissions import IsAdminUser
from common.modules.cortex_soar import CortexSOAR
from common.modules.cyware import Cyware
from common.modules.ibm_qradar import IBMQradar
from common.modules.itsm import ITSM
from integration.serializers import (
    GetIntegrationInstanceSerializer,
    GetIntegrationSerializer,
    IntegrationCredentialUpdateSerializer,
    IntegrationSerializer,
)

from .models import (
    CredentialTypes,
    Integration,
    IntegrationCredentials,
    IntegrationTypes,
    ItsmSubTypes,
    SiemSubTypes,
    SoarSubTypes,
    ThreatIntelligenceSubTypes,
)


def test_integration_connection(
    integration_type, subtype, credentials_type, credentials
):
    if (
        integration_type == IntegrationTypes.SIEM_INTEGRATION
        and subtype == SiemSubTypes.IBM_QRADAR
    ):
        if credentials_type == CredentialTypes.USERNAME_PASSWORD:
            with IBMQradar(
                username=credentials.get("username"),
                password=credentials.get("password"),
                ip_address=credentials.get("ip_address"),
                port=credentials.get("port"),
            ) as ibm_qradar:
                if not ibm_qradar.test_integration():
                    raise serializers.ValidationError(
                        "QRadar integration is not accessible."
                    )
        else:
            raise serializers.ValidationError(
                "Unsupported credential type for IBM Qradar."
            )

    elif (
        integration_type == IntegrationTypes.ITSM_INTEGRATION
        and subtype == ItsmSubTypes.MANAGE_ENGINE
    ):
        if credentials_type == CredentialTypes.API_KEY:
            with ITSM(
                ip_address=credentials.get("ip_address"),
                port=credentials.get("port"),
                token=credentials.get("api_key"),
            ) as itsm:
                if not itsm._get_accounts():
                    raise serializers.ValidationError(
                        "ManageEngine integration is not accessible."
                    )
        else:
            raise serializers.ValidationError(
                "Unsupported credential type for ManageEngine."
            )

    elif (
        integration_type == IntegrationTypes.SOAR_INTEGRATION
        and subtype == SoarSubTypes.CORTEX_SOAR
    ):
        if credentials_type == CredentialTypes.API_KEY:
            with CortexSOAR(
                ip_address=credentials.get("ip_address"),
                port=credentials.get("port"),
                token=credentials.get("api_key"),
            ) as soar:
                if not soar._get_accounts():
                    raise serializers.ValidationError(
                        "Cortex SOAR integration is not accessible."
                    )
        else:
            raise serializers.ValidationError(
                "Unsupported credential type for Cortex SOAR."
            )

    elif (
        integration_type == IntegrationTypes.THREAT_INTELLIGENCE
        and subtype == ThreatIntelligenceSubTypes.CYWARE
    ):
        if credentials_type == CredentialTypes.SECRET_KEY_ACCESS_KEY:
            with Cyware(
                base_url=credentials.get("base_url"),
                secret_key=credentials.get("secret_key"),
                access_key=credentials.get("access_key"),
            ) as cyware:
                response = cyware.get_alert_list()
                if response.status_code != 200:
                    raise serializers.ValidationError(
                        "Cyware integration is not accessible."
                    )
        else:
            raise serializers.ValidationError("Unsupported credential type for Cyware.")


class IntegrationTypesView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        siem_subtypes = [
            {"id": choice[0], "name": choice[1]} for choice in SiemSubTypes.choices
        ]
        soar_subtypes = [
            {"id": choice[0], "name": choice[1]} for choice in SoarSubTypes.choices
        ]
        itsm_subtypes = [
            {"id": choice[0], "name": choice[1]} for choice in ItsmSubTypes.choices
        ]
        threat_intelligence_subtypes = [
            {"id": choice[0], "name": choice[1]}
            for choice in ThreatIntelligenceSubTypes.choices
        ]

        integration_types = []
        for choice in IntegrationTypes.choices:
            if choice[0] == IntegrationTypes.SIEM_INTEGRATION:
                subtypes = siem_subtypes
            elif choice[0] == IntegrationTypes.SOAR_INTEGRATION:
                subtypes = soar_subtypes
            elif choice[0] == IntegrationTypes.ITSM_INTEGRATION:
                subtypes = itsm_subtypes
            elif choice[0] == IntegrationTypes.THREAT_INTELLIGENCE:
                subtypes = threat_intelligence_subtypes
            else:
                subtypes = []

            integration_types.append(
                {"id": choice[0], "name": choice[1], "sub_types": subtypes}
            )

        return Response({"data": integration_types}, status=status.HTTP_200_OK)


class CredentialTypesListAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        credential_types = [
            {"id": choice[0], "text": choice[1]} for choice in CredentialTypes.choices
        ]
        return Response(credential_types, status=status.HTTP_200_OK)


class GetIBMQradarTenants(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        logger.info("Getting IBM QRadar tenants")
        with IBMQradar() as ibm_qradar:
            data = ibm_qradar._get_tenants()
            if data:
                return Response({"data": data}, status=status.HTTP_200_OK)
        return Response({"data": []}, status=status.HTTP_200_OK)


class IntegrationCreateAPIView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = IntegrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(admin=request.user)
            return Response(
                {"message": "Integration created successfully"},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetAllIntegrationsAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        integrations = Integration.objects.all().prefetch_related("credentials")
        serializer = GetIntegrationSerializer(integrations, many=True)
        return Response(serializer.data)


class UpdateCredentialView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def put(self, request, pk):
        try:
            credential = IntegrationCredentials.objects.get(pk=pk)
        except IntegrationCredentials.DoesNotExist:
            return Response(
                {"error": "Credential not found"}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = IntegrationCredentialUpdateSerializer(
            credential, data=request.data, partial=True
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TestIntegrationAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def post(self, request, *args, **kwargs):
        data = request.data

        try:
            integration_type = data.get("integration_type", None)
            credentials = data.get("credentials", None)
            credentials_type = credentials.get("credential_type", None)

            if (
                integration_type is None
                or credentials is None
                or credentials_type is None
            ):
                return Response(
                    {"error": "Missing required fields in the request"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            subtype = (
                data.get("siem_subtype")
                or data.get("itsm_subtype")
                or data.get("soar_subtype")
                or data.get("threat_intelligence_subtype")
            )

            test_integration_connection(
                integration_type, subtype, credentials_type, credentials
            )

        except serializers.ValidationError as e:
            return Response(
                {"error": str(e.detail)}, status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        return Response(
            {"message": "Integration credentials are valid and reachable."},
            status=status.HTTP_200_OK,
        )


class GetIntegrationInstanceListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def post(self, request):
        integration_type = request.data.get("integration_type")
        siem_subtype = request.data.get("siem_subtype")
        soar_subtype = request.data.get("soar_subtype")
        itsm_subtype = request.data.get("itsm_subtype")

        # Validate integration_type
        if not integration_type or integration_type not in [
            choice[0] for choice in IntegrationTypes.choices
        ]:
            return Response(
                {"error": "Invalid or missing integration_type"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Build query filters
        filters = {"integration_type": integration_type}

        if integration_type == IntegrationTypes.SIEM_INTEGRATION:
            if siem_subtype and siem_subtype in [
                choice[0] for choice in SiemSubTypes.choices
            ]:
                filters["siem_subtype"] = siem_subtype
            elif siem_subtype is not None:
                return Response(
                    {"error": "Invalid siem_subtype"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        elif integration_type == IntegrationTypes.SOAR_INTEGRATION:
            if soar_subtype and soar_subtype in [
                choice[0] for choice in SoarSubTypes.choices
            ]:
                filters["soar_subtype"] = soar_subtype
            elif soar_subtype is not None:
                return Response(
                    {"error": "Invalid soar_subtype"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        elif integration_type == IntegrationTypes.ITSM_INTEGRATION:
            if itsm_subtype and itsm_subtype in [
                choice[0] for choice in ItsmSubTypes.choices
            ]:
                filters["itsm_subtype"] = itsm_subtype
            elif itsm_subtype is not None:
                return Response(
                    {"error": "Invalid itsm_subtype"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # Query integrations
        try:
            integrations = Integration.objects.filter(**filters)
            serializer = GetIntegrationInstanceSerializer(integrations, many=True)
            return Response(
                {
                    "message": "Integrations retrieved successfully",
                    "data": serializer.data,
                },
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
