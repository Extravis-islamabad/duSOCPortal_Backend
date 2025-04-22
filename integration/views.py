from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from .models import IntegrationTypes, ItsmSubTypes, SiemSubTypes, SoarSubTypes


class IntegrationTypesView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

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
