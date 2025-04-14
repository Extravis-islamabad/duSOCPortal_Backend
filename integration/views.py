from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from .models import IntegrationTypes


class IntegrationTypesView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        integration_types = [
            {"id": choice[0], "name": choice[1]} for choice in IntegrationTypes.choices
        ]
        return Response({"data": integration_types}, status=status.HTTP_200_OK)
