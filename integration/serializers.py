from django.core.validators import validate_ipv46_address
from rest_framework import serializers

from common.modules.cortex_soar import CortexSOAR
from common.modules.ibm_qradar import IBMQradar
from common.modules.itsm import ITSM

from .models import (
    CredentialTypes,
    Integration,
    IntegrationCredentials,
    IntegrationTypes,
    ItsmSubTypes,
    SiemSubTypes,
    SoarSubTypes,
)


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


class GetIntegrationCredentialsSerializer(serializers.ModelSerializer):
    credential_type_text = serializers.SerializerMethodField()

    class Meta:
        model = IntegrationCredentials
        fields = [
            "id",
            "credential_type",
            "credential_type_text",
            "username",
            "password",
            "api_key",
            "ip_address",
            "port",
        ]

    def get_credential_type_text(self, obj):
        return dict(CredentialTypes.choices).get(obj.credential_type)


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
        integration_type = data.get("integration_type")
        siem_subtype = data.get("siem_subtype")
        itsm_subtype = data.get("itsm_subtype")
        soar_subtype = data.get("soar_subtype")
        credentials_type = data.get("credentials").get("credential_type")
        credentials = data.get("credentials")
        # Only validate Integration itself; credentials are separate
        integration = Integration(
            **{k: v for k, v in data.items() if k != "credentials"}
        )
        integration.clean()  # triggers model validation

        # Perform actual reachability check based on type
        if (
            integration_type == IntegrationTypes.SIEM_INTEGRATION
            and siem_subtype == SiemSubTypes.IBM_QRADAR
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

        elif (
            integration_type == IntegrationTypes.ITSM_INTEGRATION
            and itsm_subtype == ItsmSubTypes.MANAGE_ENGINE
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

        elif (
            integration_type == IntegrationTypes.SOAR_INTEGRATION
            and soar_subtype == SoarSubTypes.CORTEX_SOAR
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
            raise serializers.ValidationError("Integration type not supported.")
        return data


class GetIntegrationSerializer(serializers.ModelSerializer):
    credentials = GetIntegrationCredentialsSerializer(many=True, read_only=True)
    integration_type_text = serializers.SerializerMethodField()
    siem_subtype_text = serializers.SerializerMethodField()
    soar_subtype_text = serializers.SerializerMethodField()
    itsm_subtype_text = serializers.SerializerMethodField()
    modified_by = serializers.SerializerMethodField()
    modified_by_id = serializers.SerializerMethodField()
    tenant_count = serializers.SerializerMethodField()

    class Meta:
        model = Integration
        fields = [
            "id",
            "status",
            "modified_by_id",
            "modified_by",
            "integration_type",
            "integration_type_text",
            "siem_subtype",
            "siem_subtype_text",
            "soar_subtype",
            "soar_subtype_text",
            "itsm_subtype",
            "itsm_subtype_text",
            "instance_name",
            "credentials",
            "tenant_count",
            "created_at",
            "updated_at",
        ]

    def get_integration_type_text(self, obj):
        return dict(IntegrationTypes.choices).get(obj.integration_type)

    def get_siem_subtype_text(self, obj):
        return (
            dict(SiemSubTypes.choices).get(obj.siem_subtype)
            if obj.siem_subtype
            else None
        )

    def get_soar_subtype_text(self, obj):
        return (
            dict(SoarSubTypes.choices).get(obj.soar_subtype)
            if obj.soar_subtype
            else None
        )

    def get_itsm_subtype_text(self, obj):
        return (
            dict(ItsmSubTypes.choices).get(obj.itsm_subtype)
            if obj.itsm_subtype
            else None
        )

    def get_modified_by(self, obj):
        return obj.admin.username if obj.admin else None

    def get_modified_by_id(self, obj):
        return obj.admin.id if obj.admin else None

    def get_tenant_count(self, obj):
        if obj.integration_type == IntegrationTypes.SIEM_INTEGRATION:
            return obj.du_ibm_qradar_tenants.count()
        elif obj.integration_type == IntegrationTypes.SOAR_INTEGRATION:
            return obj.du_cortex_soar_tenants.count()
        elif obj.integration_type == IntegrationTypes.ITSM_INTEGRATION:
            return obj.du_itsm_tenants.count()
        return 0


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


class GetIntegrationInstanceSerializer(serializers.ModelSerializer):
    integration_type = serializers.ChoiceField(choices=IntegrationTypes.choices)
    siem_subtype = serializers.ChoiceField(
        choices=SiemSubTypes.choices, allow_null=True, required=False
    )
    soar_subtype = serializers.ChoiceField(
        choices=SoarSubTypes.choices, allow_null=True, required=False
    )
    itsm_subtype = serializers.ChoiceField(
        choices=ItsmSubTypes.choices, allow_null=True, required=False
    )

    class Meta:
        model = Integration
        fields = [
            "id",
            "instance_name",
            "integration_type",
            "siem_subtype",
            "soar_subtype",
            "itsm_subtype",
            "status",
            "created_at",
            "updated_at",
        ]
