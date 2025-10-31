from cryptography.fernet import Fernet
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from loguru import logger
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from authentication.permissions import IsAdminUser, IsReadonlyAdminUser
from common.constants import EncryptedKeyConstants
from common.modules.cortex_soar import CortexSOAR
from common.modules.cyware import Cyware
from common.modules.ibm_qradar import IBMQradar
from common.modules.ibm_qradar_token import IBMQradarToken
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
                if not ibm_qradar.test_integration(timeout=5):
                    raise serializers.ValidationError(
                        "QRadar integration is not accessible."
                    )
        elif credentials_type == CredentialTypes.API_KEY:
            with IBMQradarToken(
                ip_address=credentials.get("ip_address"),
                port=credentials.get("port"),
                api_key=credentials.get("api_key"),
            ) as ibm_qradar_token:
                if not ibm_qradar_token.test_integration(timeout=5):
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
                if not itsm._get_accounts(timeout=5):
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
                if not soar._get_accounts(timeout=5):
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
                logger.info(
                    f"base_url: {cyware.base_url}, secret_key: {cyware.secret_key}, access_key: {cyware.access_key}"
                )
                response = cyware.get_alert_list(timeout=10)
                logger.info(f"response: {response.json()}")
                if response.status_code != 200:
                    logger.error(
                        f"Cyware.get_alert_list() Failed: {response.status_code}"
                    )
                    logger.error(f"Cyware.get_alert_list() Failed: {response.text}")
                    raise serializers.ValidationError(
                        "Cyware integration is not accessible."
                    )
        else:
            raise serializers.ValidationError("Unsupported credential type for Cyware.")
    else:
        raise serializers.ValidationError(
            "Missing or incorrect credentials for integration."
        )


class IntegrationTypesView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsReadonlyAdminUser]

    @swagger_auto_schema(
        operation_description="""Retrieves all available integration types with their subtypes.

        Returns a list of integration types (SIEM, SOAR, ITSM, Threat Intelligence)
        along with their respective subtypes.

        **Integration Types:**
        - SIEM Integration (IBM QRadar, Splunk, etc.)
        - SOAR Integration (Cortex SOAR, IBM Resilient, etc.)
        - ITSM Integration (ManageEngine, Zendesk, etc.)
        - Threat Intelligence (Cyware)

        Only admin users can access this endpoint.""",
        responses={
            200: openapi.Response(
                description="Integration types retrieved successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "data": openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Items(
                                type=openapi.TYPE_OBJECT,
                                properties={
                                    "id": openapi.Schema(type=openapi.TYPE_INTEGER),
                                    "name": openapi.Schema(type=openapi.TYPE_STRING),
                                    "sub_types": openapi.Schema(
                                        type=openapi.TYPE_ARRAY,
                                        items=openapi.Items(
                                            type=openapi.TYPE_OBJECT,
                                            properties={
                                                "id": openapi.Schema(
                                                    type=openapi.TYPE_INTEGER
                                                ),
                                                "name": openapi.Schema(
                                                    type=openapi.TYPE_STRING
                                                ),
                                            },
                                        ),
                                    ),
                                },
                            ),
                        ),
                    },
                    example={
                        "data": [
                            {
                                "id": 1,
                                "name": "SIEM Integration",
                                "sub_types": [
                                    {"id": 1, "name": "IBM QRadar"},
                                    {"id": 2, "name": "Splunk"},
                                ],
                            },
                            {
                                "id": 2,
                                "name": "SOAR Integration",
                                "sub_types": [
                                    {"id": 1, "name": "Cortex SOAR"},
                                ],
                            },
                        ]
                    },
                ),
            ),
            401: openapi.Response(
                description="Authentication credentials were not provided"
            ),
            403: openapi.Response(description="User is not an admin"),
        },
        tags=["Integration Management"],
    )
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
    permission_classes = [IsReadonlyAdminUser]

    @swagger_auto_schema(
        operation_description="""Retrieves all available credential types for integrations.

        Returns a list of supported credential types:
        - API Key
        - Username and Password
        - Secret Key and Access Key

        Only admin users can access this endpoint.""",
        responses={
            200: openapi.Response(
                description="Credential types retrieved successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Items(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            "id": openapi.Schema(type=openapi.TYPE_INTEGER),
                            "text": openapi.Schema(type=openapi.TYPE_STRING),
                        },
                    ),
                    example=[
                        {"id": 1, "text": "API Key"},
                        {"id": 2, "text": "Username and Password"},
                        {"id": 3, "text": "Secret Key and Access Key"},
                    ],
                ),
            ),
            401: openapi.Response(
                description="Authentication credentials were not provided"
            ),
            403: openapi.Response(description="User is not an admin"),
        },
        tags=["Integration Management"],
    )
    def get(self, request):
        credential_types = [
            {"id": choice[0], "text": choice[1]} for choice in CredentialTypes.choices
        ]
        return Response(credential_types, status=status.HTTP_200_OK)


class IntegrationCreateAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="""Creates a new integration with its credentials.

        This endpoint validates the integration credentials by testing the actual connection
        to the specified integration service (SIEM, SOAR, ITSM, or Threat Intelligence).

        **Required Fields:**
        - integration_type: Type of integration (1=SIEM, 2=SOAR, 3=ITSM, 4=Threat Intelligence)
        - Corresponding subtype (siem_subtype, soar_subtype, itsm_subtype, or threat_intelligence_subtype)
        - instance_name: Unique name for this integration instance
        - credentials: Credential details based on credential_type

        **Credential Types:**
        - API Key (1): Requires api_key, ip_address, port
        - Username/Password (2): Requires username, password, ip_address, port
        - Secret/Access Key (3): Requires secret_key, access_key, base_url

        Only admin users can create integrations.""",
        request_body=IntegrationSerializer,
        responses={
            201: openapi.Response(
                description="Integration created successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "message": openapi.Schema(type=openapi.TYPE_STRING),
                    },
                    example={"message": "Integration created successfully"},
                ),
            ),
            400: openapi.Response(
                description="Bad request - validation errors or connection test failed",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    example={
                        "integration_type": ["This field is required."],
                        "credentials": {"api_key": ["This field is required."]},
                    },
                ),
            ),
            401: openapi.Response(
                description="Authentication credentials were not provided"
            ),
            403: openapi.Response(description="User is not an admin"),
        },
        tags=["Integration Management"],
    )
    def post(self, request, *args, **kwargs):
        serializer = IntegrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(created_by=request.user, modified_by=request.user)
            return Response(
                {"message": "Integration created successfully"},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetAllIntegrationsAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsReadonlyAdminUser]

    @swagger_auto_schema(
        operation_description="""Retrieves all integrations with their credentials and metadata.

        Returns a list of all configured integrations including:
        - Integration details (type, subtype, instance name)
        - Encrypted credentials
        - Tenant count
        - Assets count
        - Status and timestamps

        Credentials in the response are encrypted for security.
        Only admin users can access this endpoint.""",
        responses={
            200: openapi.Response(
                description="Integrations retrieved successfully",
                schema=GetIntegrationSerializer(many=True),
            ),
            401: openapi.Response(
                description="Authentication credentials were not provided"
            ),
            403: openapi.Response(description="User is not an admin"),
        },
        tags=["Integration Management"],
    )
    def get(self, request):
        integrations = Integration.objects.all().prefetch_related("credentials")
        serializer = GetIntegrationSerializer(integrations, many=True)
        return Response(serializer.data)


class DecryptCredentialsAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="""Decrypts encrypted credential fields.

        This endpoint accepts encrypted credential values and returns their decrypted form.
        Used for displaying credentials in the admin UI.

        **Supported Fields:**
        - username
        - password
        - api_key
        - access_key
        - secret_key
        - base_url
        - ip_address

        Only admin users can decrypt credentials.""",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "username": openapi.Schema(
                    type=openapi.TYPE_STRING, description="Encrypted username"
                ),
                "password": openapi.Schema(
                    type=openapi.TYPE_STRING, description="Encrypted password"
                ),
                "api_key": openapi.Schema(
                    type=openapi.TYPE_STRING, description="Encrypted API key"
                ),
                "access_key": openapi.Schema(
                    type=openapi.TYPE_STRING, description="Encrypted access key"
                ),
                "secret_key": openapi.Schema(
                    type=openapi.TYPE_STRING, description="Encrypted secret key"
                ),
                "base_url": openapi.Schema(
                    type=openapi.TYPE_STRING, description="Encrypted base URL"
                ),
                "ip_address": openapi.Schema(
                    type=openapi.TYPE_STRING, description="Encrypted IP address"
                ),
            },
        ),
        responses={
            200: openapi.Response(
                description="Credentials decrypted successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "username": openapi.Schema(
                            type=openapi.TYPE_STRING, nullable=True
                        ),
                        "password": openapi.Schema(
                            type=openapi.TYPE_STRING, nullable=True
                        ),
                        "api_key": openapi.Schema(
                            type=openapi.TYPE_STRING, nullable=True
                        ),
                        "access_key": openapi.Schema(
                            type=openapi.TYPE_STRING, nullable=True
                        ),
                        "secret_key": openapi.Schema(
                            type=openapi.TYPE_STRING, nullable=True
                        ),
                        "base_url": openapi.Schema(
                            type=openapi.TYPE_STRING, nullable=True
                        ),
                        "ip_address": openapi.Schema(
                            type=openapi.TYPE_STRING, nullable=True
                        ),
                    },
                    example={
                        "username": "admin",
                        "password": "decrypted_password",
                        "api_key": None,
                        "access_key": None,
                        "secret_key": None,
                        "base_url": None,
                        "ip_address": "192.168.1.100",
                    },
                ),
            ),
            401: openapi.Response(
                description="Authentication credentials were not provided"
            ),
            403: openapi.Response(description="User is not an admin"),
        },
        tags=["Integration Management"],
    )
    def post(self, request):
        fernet = Fernet(EncryptedKeyConstants.ENCRYPTED_KEY.encode())

        encrypted_fields = {
            "username": request.data.get("username"),
            "password": request.data.get("password"),
            "api_key": request.data.get("api_key"),
            "access_key": request.data.get("access_key"),
            "secret_key": request.data.get("secret_key"),
            "base_url": request.data.get("base_url"),
            "ip_address": request.data.get("ip_address"),
        }

        result = {}

        for field, encrypted_value in encrypted_fields.items():
            if encrypted_value:
                try:
                    result[field] = fernet.decrypt(encrypted_value.encode()).decode()
                except Exception as e:
                    result[field] = f"[DECRYPTION FAILED] {str(e)}"
            else:
                result[field] = None

        return Response(result, status=status.HTTP_200_OK)


class UpdateCredentialView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="""Updates integration credentials and validates the connection.

        This endpoint updates existing integration credentials and tests the connection
        to ensure the new credentials are valid and the integration is reachable.

        The credential_type determines which fields are required:
        - API Key: api_key, ip_address, port
        - Username/Password: username, password, ip_address, port
        - Secret/Access Key: secret_key, access_key, base_url

        Only admin users can update credentials.""",
        manual_parameters=[
            openapi.Parameter(
                "pk",
                openapi.IN_PATH,
                description="ID of the credential to update",
                type=openapi.TYPE_INTEGER,
                required=True,
            ),
        ],
        request_body=IntegrationCredentialUpdateSerializer,
        responses={
            200: openapi.Response(
                description="Credential updated successfully",
                schema=IntegrationCredentialUpdateSerializer,
            ),
            400: openapi.Response(
                description="Bad request - validation errors or connection test failed",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    example={"error": "QRadar integration is not accessible."},
                ),
            ),
            401: openapi.Response(
                description="Authentication credentials were not provided"
            ),
            403: openapi.Response(description="User is not an admin"),
            404: openapi.Response(
                description="Credential not found",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"error": openapi.Schema(type=openapi.TYPE_STRING)},
                    example={"error": "Credential not found"},
                ),
            ),
        },
        tags=["Integration Management"],
    )
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

    @swagger_auto_schema(
        operation_description="""Tests integration credentials before creating/updating an integration.

        This endpoint validates that the provided credentials can successfully connect
        to the target integration service without saving anything to the database.

        **Use Case:** Test credentials before creating a new integration.

        **Required Fields:**
        - integration_type: Type of integration (1=SIEM, 2=SOAR, 3=ITSM, 4=Threat Intelligence)
        - Subtype field (siem_subtype, soar_subtype, itsm_subtype, or threat_intelligence_subtype)
        - credentials object with credential_type and required fields

        **Supported Integrations:**
        - IBM QRadar (SIEM) - Username/Password or API Key
        - ManageEngine (ITSM) - API Key
        - Cortex SOAR (SOAR) - API Key
        - Cyware (Threat Intelligence) - Secret Key and Access Key

        Only admin users can test integrations.""",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "integration_type": openapi.Schema(
                    type=openapi.TYPE_INTEGER,
                    description="Integration type (1=SIEM, 2=SOAR, 3=ITSM, 4=Threat Intel)",
                    default=1,
                ),
                "siem_subtype": openapi.Schema(
                    type=openapi.TYPE_INTEGER,
                    description="SIEM subtype (1=IBM QRadar, 2=Splunk)",
                    nullable=True,
                ),
                "credentials": openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "credential_type": openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description="Credential type (1=API Key, 2=Username/Password, 3=Secret/Access Key)",
                        ),
                        "ip_address": openapi.Schema(type=openapi.TYPE_STRING),
                        "port": openapi.Schema(type=openapi.TYPE_INTEGER),
                        "username": openapi.Schema(
                            type=openapi.TYPE_STRING, nullable=True
                        ),
                        "password": openapi.Schema(
                            type=openapi.TYPE_STRING, nullable=True
                        ),
                        "api_key": openapi.Schema(
                            type=openapi.TYPE_STRING, nullable=True
                        ),
                        "base_url": openapi.Schema(
                            type=openapi.TYPE_STRING, nullable=True
                        ),
                        "access_key": openapi.Schema(
                            type=openapi.TYPE_STRING, nullable=True
                        ),
                        "secret_key": openapi.Schema(
                            type=openapi.TYPE_STRING, nullable=True
                        ),
                    },
                ),
            },
            example={
                "integration_type": 1,
                "siem_subtype": 1,
                "credentials": {
                    "credential_type": 2,
                    "ip_address": "192.168.1.100",
                    "port": 443,
                    "username": "admin",
                    "password": "password123",
                },
            },
        ),
        responses={
            200: openapi.Response(
                description="Integration connection successful",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"message": openapi.Schema(type=openapi.TYPE_STRING)},
                    example={
                        "message": "Integration credentials are valid and reachable."
                    },
                ),
            ),
            400: openapi.Response(
                description="Bad request - missing fields or connection failed",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"error": openapi.Schema(type=openapi.TYPE_STRING)},
                    example={"error": "QRadar integration is not accessible."},
                ),
            ),
            401: openapi.Response(
                description="Authentication credentials were not provided"
            ),
            403: openapi.Response(description="User is not an admin"),
        },
        tags=["Integration Testing"],
    )
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

            if subtype is None:
                return Response(
                    {"error": "Missing required fields in the request"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            test_integration_connection(
                integration_type, subtype, credentials_type, credentials
            )

        except serializers.ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return Response(
            {"message": "Integration credentials are valid and reachable."},
            status=status.HTTP_200_OK,
        )


class TestIntegrationConnectionAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsReadonlyAdminUser]

    @swagger_auto_schema(
        operation_description="""Tests the connection of an existing integration.

        This endpoint validates that an existing integration's stored credentials
        can still successfully connect to the target service.

        **Use Case:** Verify existing integration health/connectivity.

        The integration ID must exist in the database and have associated credentials.

        Only admin users can test integration connections.""",
        manual_parameters=[
            openapi.Parameter(
                "integration_id",
                openapi.IN_PATH,
                description="ID of the integration to test",
                type=openapi.TYPE_INTEGER,
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description="Integration connection successful",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"message": openapi.Schema(type=openapi.TYPE_STRING)},
                    example={"message": "Integration connection successful."},
                ),
            ),
            400: openapi.Response(
                description="Bad request - no credentials or connection failed",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"error": openapi.Schema(type=openapi.TYPE_STRING)},
                    example={"error": "No credentials found for this integration."},
                ),
            ),
            401: openapi.Response(
                description="Authentication credentials were not provided"
            ),
            403: openapi.Response(description="User is not an admin"),
            404: openapi.Response(
                description="Integration not found",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"error": openapi.Schema(type=openapi.TYPE_STRING)},
                    example={"error": "Integration not found."},
                ),
            ),
            500: openapi.Response(
                description="Internal server error",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"error": openapi.Schema(type=openapi.TYPE_STRING)},
                    example={"error": "Connection test failed: <error_details>"},
                ),
            ),
        },
        tags=["Integration Testing"],
    )
    def get(self, request, integration_id):
        try:
            integration = Integration.objects.get(id=integration_id)
        except Integration.DoesNotExist:
            return Response({"error": "Integration not found."}, status=404)

        credentials = integration.credentials.first()
        if not credentials:
            return Response(
                {"error": "No credentials found for this integration."}, status=400
            )

        credentials_data = {
            "username": credentials.username,
            "password": credentials.password,
            "api_key": credentials.api_key,
            "access_key": credentials.access_key,
            "secret_key": credentials.secret_key,
            "ip_address": credentials.ip_address,
            "port": credentials.port,
            "base_url": credentials.base_url,
        }

        try:
            test_integration_connection(
                integration_type=integration.integration_type,
                subtype=(
                    integration.siem_subtype
                    or integration.soar_subtype
                    or integration.itsm_subtype
                    or integration.threat_intelligence_subtype
                ),
                credentials_type=credentials.credential_type,
                credentials=credentials_data,
            )
            return Response(
                {"message": "Integration connection successful."}, status=200
            )

        except serializers.ValidationError as ve:
            return Response({"error": str(ve.detail)}, status=400)

        except Exception as e:
            return Response({"error": str(e)}, status=500)


class GetIntegrationInstanceListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsReadonlyAdminUser]

    @swagger_auto_schema(
        operation_description="""Retrieves integration instances filtered by type and subtype.

        Returns a list of integration instances matching the specified integration type
        and optional subtype filter.

        **Use Case:** Get available integration instances for tenant assignment.

        **Filtering:**
        - Required: integration_type (1=SIEM, 2=SOAR, 3=ITSM, 4=Threat Intelligence)
        - Optional: Corresponding subtype field to further filter results

        Only admin users can access this endpoint.""",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "integration_type": openapi.Schema(
                    type=openapi.TYPE_INTEGER,
                    description="Integration type (1=SIEM, 2=SOAR, 3=ITSM, 4=Threat Intel)",
                    default=1,
                ),
                "siem_subtype": openapi.Schema(
                    type=openapi.TYPE_INTEGER,
                    description="SIEM subtype (1=IBM QRadar, 2=Splunk) - optional filter",
                    nullable=True,
                ),
                "soar_subtype": openapi.Schema(
                    type=openapi.TYPE_INTEGER,
                    description="SOAR subtype (1=Cortex SOAR, 2=IBM Resilient) - optional filter",
                    nullable=True,
                ),
                "itsm_subtype": openapi.Schema(
                    type=openapi.TYPE_INTEGER,
                    description="ITSM subtype (1=ManageEngine, 2=Zendesk) - optional filter",
                    nullable=True,
                ),
            },
            required=["integration_type"],
            example={
                "integration_type": 1,
                "siem_subtype": 1,
            },
        ),
        responses={
            200: openapi.Response(
                description="Integrations retrieved successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "message": openapi.Schema(type=openapi.TYPE_STRING),
                        "data": openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Items(
                                type=openapi.TYPE_OBJECT,
                                properties={
                                    "id": openapi.Schema(type=openapi.TYPE_INTEGER),
                                    "instance_name": openapi.Schema(
                                        type=openapi.TYPE_STRING
                                    ),
                                    "integration_type": openapi.Schema(
                                        type=openapi.TYPE_INTEGER
                                    ),
                                    "siem_subtype": openapi.Schema(
                                        type=openapi.TYPE_INTEGER, nullable=True
                                    ),
                                    "soar_subtype": openapi.Schema(
                                        type=openapi.TYPE_INTEGER, nullable=True
                                    ),
                                    "itsm_subtype": openapi.Schema(
                                        type=openapi.TYPE_INTEGER, nullable=True
                                    ),
                                    "status": openapi.Schema(type=openapi.TYPE_BOOLEAN),
                                    "created_at": openapi.Schema(
                                        type=openapi.TYPE_STRING, format="date-time"
                                    ),
                                    "updated_at": openapi.Schema(
                                        type=openapi.TYPE_STRING, format="date-time"
                                    ),
                                },
                            ),
                        ),
                    },
                    example={
                        "message": "Integrations retrieved successfully",
                        "data": [
                            {
                                "id": 1,
                                "instance_name": "QRadar Production",
                                "integration_type": 1,
                                "siem_subtype": 1,
                                "soar_subtype": None,
                                "itsm_subtype": None,
                                "status": True,
                                "created_at": "2024-01-15T10:30:00Z",
                                "updated_at": "2024-01-20T14:45:00Z",
                            },
                        ],
                    },
                ),
            ),
            400: openapi.Response(
                description="Bad request - invalid parameters",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"error": openapi.Schema(type=openapi.TYPE_STRING)},
                    example={"error": "Invalid or missing integration_type"},
                ),
            ),
            401: openapi.Response(
                description="Authentication credentials were not provided"
            ),
            403: openapi.Response(description="User is not an admin"),
        },
        tags=["Integration Management"],
    )
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
