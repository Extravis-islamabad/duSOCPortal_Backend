# tenant/serializers.py
from rest_framework import serializers

from .models import Tenant, TenantPermissionChoices, TenantRole, TenantRolePermissions


class TenantCreateSerializer(serializers.ModelSerializer):
    permissions = serializers.ListField(
        child=serializers.IntegerField(min_value=1, max_value=5),
        required=False,
        help_text="List of permission integers from TenantPermissionChoices (1-5) to assign to the tenant",
    )

    class Meta:
        model = Tenant
        fields = ["name", "password", "email", "phone_number", "permissions"]

    def validate_name(self, value):
        """Check if a tenant with this name already exists."""
        if value and Tenant.objects.filter(name=value).exists():
            raise serializers.ValidationError(
                f"A tenant with the name '{value}' already exists."
            )
        return value

    def validate_email(self, value):
        """Check if a tenant with this contact_email already exists."""
        if value and Tenant.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                f"A tenant with the email '{value}' already exists."
            )
        return value

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

    def create(self, validated_data):
        permissions = validated_data.pop("permissions", [])
        user = self.context["request"].user

        tenant = Tenant(
            created_by=user,
            name=validated_data.get("name"),
            email=validated_data.get("email"),
            phone_number=validated_data.get("phone_number"),
        )
        raw_password = validated_data.get("password")
        if raw_password:
            tenant.set_password(raw_password)
        else:
            tenant.password = None
        tenant.save()

        role = TenantRole.objects.create(
            tenant=tenant,
            name=f"{tenant.name or 'Tenant'} Admin",
            role_type=TenantRole.TenantRoleChoices.TENANT_ADMIN,
        )

        for perm_value in permissions:
            TenantRolePermissions.objects.create(role=role, permission=perm_value)

        return tenant
