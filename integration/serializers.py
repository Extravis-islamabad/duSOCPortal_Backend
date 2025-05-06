from rest_framework import serializers

from .models import Integration, IntegrationCredentials


class IntegrationCredentialsSerializer(serializers.ModelSerializer):
    class Meta:
        model = IntegrationCredentials
        exclude = ["integration"]  # Foreign key is added in parent

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data.pop("api_key", None)
        data.pop("password", None)
        return data


class IntegrationSerializer(serializers.ModelSerializer):
    credentials = IntegrationCredentialsSerializer()

    class Meta:
        model = Integration
        fields = [
            "integration_type",
            "siem_subtype",
            "soar_subtype",
            "itsm_subtype",
            "instance_name",
            "instance_type",
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
