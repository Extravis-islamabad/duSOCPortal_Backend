from django.contrib.auth.hashers import make_password
from django.db import transaction
from rest_framework import serializers

from .models import Integration, IntegrationCredentials, IntegrationTypes


class IntegrationCredentialsSerializer(serializers.ModelSerializer):
    class Meta:
        model = IntegrationCredentials
        fields = ["username", "password", "ip_address", "port"]

    def validate_password(self, value):
        # Use Django's secure password hashing
        return make_password(value)

    def to_representation(self, instance):
        # Exclude password from response
        representation = super().to_representation(instance)
        representation.pop("password", None)
        return representation


class IntegrationSerializer(serializers.ModelSerializer):
    credentials = IntegrationCredentialsSerializer(many=True)

    class Meta:
        model = Integration
        fields = [
            "integration_type",
            "siem_subtype",
            "soar_subtype",
            "itsm_subtype",
            "instance_name",
            "instance_type",
            "api_key",
            "version",
            "credentials",
        ]

    def validate(self, data):
        integration_type = data.get("integration_type")
        siem_subtype = data.get("siem_subtype")
        soar_subtype = data.get("soar_subtype")
        itsm_subtype = data.get("itsm_subtype")
        api_key = data.get("api_key")
        credentials = data.get("credentials")

        # Validate subtype requirements based on integration type
        if integration_type == IntegrationTypes.SIEM_INTEGRATION:
            if not siem_subtype:
                raise serializers.ValidationError(
                    {"siem_subtype": "SIEM subtype is required for SIEM Integration."}
                )
            if soar_subtype or itsm_subtype:
                raise serializers.ValidationError(
                    "Only siem_subtype should be provided for SIEM Integration."
                )
        elif integration_type == IntegrationTypes.SOAR_INTEGRATION:
            if not soar_subtype:
                raise serializers.ValidationError(
                    {"soar_subtype": "SOAR subtype is required for SOAR Integration."}
                )
            if siem_subtype or itsm_subtype:
                raise serializers.ValidationError(
                    "Only soar_subtype should be provided for SOAR Integration."
                )
        elif integration_type == IntegrationTypes.ITSM_INTEGRATION:
            if not itsm_subtype:
                raise serializers.ValidationError(
                    {"itsm_subtype": "ITSM subtype is required for ITSM Integration."}
                )
            if siem_subtype or soar_subtype:
                raise serializers.ValidationError(
                    "Only itsm_subtype should be provided for ITSM Integration."
                )

        # Validate credentials
        if not credentials:
            raise serializers.ValidationError(
                {"credentials": "At least one set of credentials is required."}
            )

        # Validate that either api_key or (username and password) is provided
        has_valid_credentials = False
        for cred in credentials:
            username = cred.get("username")
            password = cred.get("password")
            if username and password:
                has_valid_credentials = True
                break

        if not (api_key or has_valid_credentials):
            raise serializers.ValidationError(
                {
                    "non_field_errors": "Either an api_key or both username and password in credentials must be provided."
                }
            )

        return data

    def create(self, validated_data):
        credentials_data = validated_data.pop("credentials")
        with transaction.atomic():
            integration = Integration.objects.create(**validated_data)
            for cred_data in credentials_data:
                IntegrationCredentials.objects.create(
                    integration=integration, **cred_data
                )
        return integration
