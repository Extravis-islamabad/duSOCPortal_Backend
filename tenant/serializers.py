# tenant/serializers.py
from rest_framework import serializers

from authentication.models import User
from integration.models import (
    Integration,
    IntegrationTypes,
    ItsmSubTypes,
    SiemSubTypes,
    SoarSubTypes,
)

from .models import (
    DuIbmQradarTenants,
    Tenant,
    TenantPermissionChoices,
    TenantRole,
    TenantRolePermissions,
)


class TenantUpdateSerializer(serializers.ModelSerializer):
    permissions = serializers.ListField(
        child=serializers.IntegerField(min_value=1, max_value=5),
        required=False,
        help_text="List of permission integers from TenantPermissionChoices (1-5) to assign to the tenant",
    )

    class Meta:
        model = Tenant
        fields = ["permissions"]  # Only permissions can be updated

    def validate_permissions(self, value):
        """Ensure all provided permissions are valid choices."""
        valid_choices = [choice.value for choice in TenantPermissionChoices]
        if value:
            invalid = [p for p in value if p not in valid_choices]
            if invalid:
                raise serializers.ValidationError(
                    f"Invalid permissions: {invalid}. Must be one of {valid_choices}"
                )
        return value

    def update(self, instance, validated_data):
        # Extract permissions (if provided)
        permissions = validated_data.pop("permissions", None)

        # No fields to update on the Tenant model itself, just save to trigger updated_at
        instance.save()

        # Update permissions only if provided
        if permissions is not None:
            # Get or create the tenant's role
            role, _ = TenantRole.objects.get_or_create(
                tenant=instance,
                defaults={
                    "name": f"{instance.tenant.username} Admin",
                    "role_type": TenantRole.TenantRoleChoices.TENANT_ADMIN,
                },
            )
            # Clear existing permissions
            TenantRolePermissions.objects.filter(role=role).delete()
            # Add new permissions
            for perm_value in permissions:
                TenantRolePermissions.objects.create(role=role, permission=perm_value)

        return instance


class TenantRolePermissionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = TenantRolePermissions
        fields = ["permission", "permission_text"]


class TenantDetailSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="tenant.username", read_only=True)
    email = serializers.EmailField(source="tenant.email", read_only=True)
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = Tenant
        fields = [
            "id",
            "username",
            "email",
            "phone_number",
            "created_at",
            "updated_at",
            "permissions",
        ]

    def get_permissions(self, obj):
        try:
            role = obj.roles.get()  # Assumes one role per tenant
            return [
                {"id": perm.permission, "name": perm.permission_text}
                for perm in role.role_permissions.all()
            ]
        except TenantRole.DoesNotExist:
            return []


class TenantPermissionSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(source="permission")
    text = serializers.CharField(source="permission_text")

    class Meta:
        model = TenantRolePermissions
        fields = ["id", "text"]


class TenantRoleSerializer(serializers.ModelSerializer):
    role_permissions = TenantPermissionSerializer(many=True, read_only=True)

    class Meta:
        model = TenantRole
        fields = ["id", "name", "role_type", "role_permissions"]


class TenantCreateSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=100, write_only=True)
    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(write_only=True, style={"input_type": "password"})
    phone_number = serializers.CharField(
        max_length=20, required=False, allow_blank=True
    )
    permissions = serializers.ListField(
        child=serializers.IntegerField(min_value=1, max_value=5),
        required=False,
        help_text="List of permission integers from TenantPermissionChoices (1-5)",
    )
    integration_type = serializers.ChoiceField(
        choices=IntegrationTypes.choices, required=True, help_text="Type of integration"
    )
    siem_subtype = serializers.ChoiceField(
        choices=SiemSubTypes.choices, required=False, allow_null=True
    )
    soar_subtype = serializers.ChoiceField(
        choices=SoarSubTypes.choices, required=False, allow_null=True
    )
    itsm_subtype = serializers.ChoiceField(
        choices=ItsmSubTypes.choices, required=False, allow_null=True
    )
    instance_name = serializers.CharField(max_length=100, required=True)
    instance_type = serializers.CharField(max_length=100, required=True)
    api_key = serializers.CharField(max_length=100, required=True)
    version = serializers.CharField(max_length=100, required=True)
    qradar_tenant_id = serializers.IntegerField(
        required=True, help_text="ID of the associated DuIbmQradarTenants"
    )

    class Meta:
        model = Tenant
        fields = [
            "username",
            "email",
            "password",
            "phone_number",
            "permissions",
            "integration_type",
            "siem_subtype",
            "soar_subtype",
            "itsm_subtype",
            "instance_name",
            "instance_type",
            "api_key",
            "version",
            "qradar_tenant_id",
        ]

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError(
                f"A user with the username '{value}' already exists."
            )
        return value

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                f"A user with the email '{value}' already exists."
            )
        return value

    def validate_permissions(self, value):
        valid_choices = [choice.value for choice in TenantPermissionChoices]
        if value:
            invalid = [p for p in value if p not in valid_choices]
            if invalid:
                raise serializers.ValidationError(
                    f"Invalid permissions: {invalid}. Must be one of {valid_choices}"
                )
        return value

    def validate_qradar_tenant_id(self, value):
        # Check if the qradar_tenant_id exists
        if not DuIbmQradarTenants.objects.filter(id=value).exists():
            raise serializers.ValidationError(
                f"No DuIbmQradarTenants found with ID {value}"
            )
        # Check if a tenant already exists with this qradar_tenant_id
        if Tenant.objects.filter(qradar_tenant__id=value).exists():
            raise serializers.ValidationError(
                f"A tenant already exists for DuIbmQradarTenants ID {value}"
            )
        return value

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
        elif integration_type == IntegrationTypes.SOAR_INTEGRATION:
            if not soar_subtype:
                raise serializers.ValidationError(
                    {
                        "soar_subtype": "SOAR subtype is required for SOAR Integration type."
                    }
                )
        elif integration_type == IntegrationTypes.ITSM_INTEGRATION:
            if not itsm_subtype:
                raise serializers.ValidationError(
                    {
                        "itsm_subtype": "ITSM subtype is required for ITSM Integration type."
                    }
                )
        return data

    def create(self, validated_data):
        permissions = validated_data.pop("permissions", [])
        integration_type = validated_data.pop("integration_type")
        siem_subtype = validated_data.pop("siem_subtype", None)
        soar_subtype = validated_data.pop("soar_subtype", None)
        itsm_subtype = validated_data.pop("itsm_subtype", None)
        instance_name = validated_data.pop("instance_name")
        instance_type = validated_data.pop("instance_type")
        api_key = validated_data.pop("api_key")
        version = validated_data.pop("version")
        qradar_tenant_id = validated_data.pop("qradar_tenant_id")

        user_data = {
            "username": validated_data.pop("username"),
            "email": validated_data.pop("email"),
            "is_tenant": True,
        }
        raw_password = validated_data.pop("password")
        phone_number = validated_data.pop("phone_number", None)

        # Create User instance
        user = User(**user_data)
        user.set_password(raw_password)
        user.save()

        # Get qradar tenant
        qradar_tenant = DuIbmQradarTenants.objects.get(id=qradar_tenant_id)

        # Create Tenant instance
        tenant = Tenant(
            tenant=user,
            created_by=self.context["request"].user,
            phone_number=phone_number,
            qradar_tenant=qradar_tenant,
        )
        tenant.save()

        # Create TenantRole
        role = TenantRole.objects.create(
            tenant=tenant,
            name=f"{user.username} Admin",
            role_type=TenantRole.TenantRoleChoices.TENANT_ADMIN,
        )

        # Assign permissions
        for perm_value in permissions:
            TenantRolePermissions.objects.create(role=role, permission=perm_value)

        # Create Integration
        integration = Integration(
            tenant=tenant,
            integration_type=integration_type,
            siem_subtype=siem_subtype,
            soar_subtype=soar_subtype,
            itsm_subtype=itsm_subtype,
            instance_name=instance_name,
            instance_type=instance_type,
            api_key=api_key,
            version=version,
        )
        integration.save()

        return tenant


class DuIbmQradarTenantsSerializer(serializers.ModelSerializer):
    qradar_tenant_id = serializers.IntegerField(source="id", read_only=True)

    class Meta:
        model = DuIbmQradarTenants
        fields = ["qradar_tenant_id", "name"]
