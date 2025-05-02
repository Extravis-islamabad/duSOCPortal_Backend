from rest_framework import serializers

from integration.models import (
    Integration,
    IntegrationTypes,
    ItsmSubTypes,
    SiemSubTypes,
    SoarSubTypes,
)


class IntegrationSerializer(serializers.ModelSerializer):
    integration_type = serializers.ChoiceField(choices=IntegrationTypes.choices)
    siem_subtype = serializers.ChoiceField(
        choices=SiemSubTypes.choices, required=False, allow_null=True
    )
    soar_subtype = serializers.ChoiceField(
        choices=SoarSubTypes.choices, required=False, allow_null=True
    )
    itsm_subtype = serializers.ChoiceField(
        choices=ItsmSubTypes.choices, required=False, allow_null=True
    )

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
        ]

    def validate(self, data):
        integration_type = data.get("integration_type")
        siem_subtype = data.get("siem_subtype")
        soar_subtype = data.get("soar_subtype")
        itsm_subtype = data.get("itsm_subtype")

        if integration_type == IntegrationTypes.SIEM_INTEGRATION:
            if not siem_subtype:
                raise serializers.ValidationError(
                    {
                        "siem_subtype": "SIEM subtype is required for SIEM Integration type."
                    }
                )
            if soar_subtype or itsm_subtype:
                raise serializers.ValidationError(
                    "Only siem_subtype should be set for SIEM Integration type."
                )
        elif integration_type == IntegrationTypes.SOAR_INTEGRATION:
            if not soar_subtype:
                raise serializers.ValidationError(
                    {
                        "soar_subtype": "SOAR subtype is required for SOAR Integration type."
                    }
                )
            if siem_subtype or itsm_subtype:
                raise serializers.ValidationError(
                    "Only soar_subtype should be set for SOAR Integration type."
                )
        elif integration_type == IntegrationTypes.ITSM_INTEGRATION:
            if not itsm_subtype:
                raise serializers.ValidationError(
                    {
                        "itsm_subtype": "ITSM subtype is required for ITSM Integration type."
                    }
                )
            if siem_subtype or soar_subtype:
                raise serializers.ValidationError(
                    "Only itsm_subtype should be set for ITSM Integration type."
                )

        return data
