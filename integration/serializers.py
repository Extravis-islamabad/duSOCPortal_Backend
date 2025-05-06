from django.core.validators import validate_ipv46_address
from rest_framework import serializers

from .models import CredentialTypes, Integration, IntegrationCredentials


class IntegrationCredentialsSerializer(serializers.ModelSerializer):
    class Meta:
        model = IntegrationCredentials
        exclude = ["integration"]  # Foreign key is added in parent

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data.pop("api_key", None)
        data.pop("password", None)
        return data

    def validate_ip_address(self, value):
        try:
            validate_ipv46_address(value)
        except Exception:
            raise serializers.ValidationError("Invalid IP address format.")
        return value


class IntegrationSerializer(serializers.ModelSerializer):
    credentials = IntegrationCredentialsSerializer()

    class Meta:
        model = Integration
        fields = [
            "id",
            "admin",
            "integration_type",
            "siem_subtype",
            "soar_subtype",
            "itsm_subtype",
            "instance_name",
            "credentials",
        ]

    def create(self, validated_data):
        credentials_data = validated_data.pop("credentials")
        integration = Integration.objects.create(**validated_data)
        IntegrationCredentials.objects.create(
            integration=integration, **credentials_data
        )
        return integration

    def validate(self, data):
        # Only validate Integration itself; credentials are separate
        integration = Integration(
            **{k: v for k, v in data.items() if k != "credentials"}
        )
        integration.clean()  # triggers model validation
        return data


class GetIntegrationSerializer(serializers.ModelSerializer):
    credentials = IntegrationCredentialsSerializer(many=True, read_only=True)

    class Meta:
        model = Integration
        fields = [
            "id",
            "status",
            "admin",
            "integration_type",
            "siem_subtype",
            "soar_subtype",
            "itsm_subtype",
            "instance_name",
            "credentials",
        ]


class IntegrationCredentialUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = IntegrationCredentials
        fields = ["id", "credential_type", "username", "password", "ip_address", "port"]


class TestCredentialSerializer(serializers.Serializer):
    credential_type = serializers.IntegerField()
    ip_address = serializers.IPAddressField()
    port = serializers.IntegerField()
    username = serializers.CharField(required=False, allow_blank=True)
    password = serializers.CharField(required=False, allow_blank=True)
    api_key = serializers.CharField(required=False, allow_blank=True)

    def validate(self, data):
        credential_type = data.get("credential_type")

        if credential_type == CredentialTypes.USERNAME_PASSWORD:  # Basic Auth
            if not data.get("username") or not data.get("password"):
                raise serializers.ValidationError(
                    "Username and password are required for Basic Auth."
                )

        elif credential_type == CredentialTypes.API_KEY:  # API Key Auth
            if not data.get("api_key"):
                raise serializers.ValidationError(
                    "API Key is required for API Key Auth."
                )

        else:
            raise serializers.ValidationError("Unsupported credential type.")

        return data
