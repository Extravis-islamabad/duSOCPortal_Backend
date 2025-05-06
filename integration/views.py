from loguru import logger
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from authentication.permissions import IsAdminUser
from common.modules.ibm_qradar import IBMQradar
from integration.serializers import IntegrationSerializer

from .models import (
    CredentialTypes,
    Integration,
    IntegrationTypes,
    ItsmSubTypes,
    SiemSubTypes,
    SoarSubTypes,
)


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

        integration_types = [
            {
                "id": choice[0],
                "name": choice[1],
                "sub_types": (
                    siem_subtypes
                    if choice[0] == IntegrationTypes.SIEM_INTEGRATION
                    else soar_subtypes
                    if choice[0] == IntegrationTypes.SOAR_INTEGRATION
                    else itsm_subtypes
                ),
            }
            for choice in IntegrationTypes.choices
        ]
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
            serializer.save()
            return Response(
                {"message": "Integration created successfully"},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetAllIntegrationsAPIView(APIView):
    def get(self, request):
        integrations = Integration.objects.all().prefetch_related("credentials")
        serializer = IntegrationSerializer(integrations, many=True)
        return Response(serializer.data)
