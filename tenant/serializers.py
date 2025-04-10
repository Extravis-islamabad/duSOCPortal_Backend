# tenant/serializers.py
from rest_framework import serializers

from .models import Tenant, TenantPermissionChoices, TenantRole, TenantRolePermissions


class TenantCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tenant
        fields = ["name", "password", "contact_email", "phone_number"]

    def create(self, validated_data):
        # Extract the authenticated user from the request context
        user = self.context["request"].user

        # Create the tenant
        tenant = Tenant(
            created_by=user,
            name=validated_data.get("name"),
            contact_email=validated_data.get("contact_email"),
            phone_number=validated_data.get("phone_number"),
        )
        tenant.set_password(validated_data["password"])
        tenant.save()

        # Create a default role for the tenant (e.g., "Tenant Admin")
        role = TenantRole.objects.create(
            user=user,
            name=TenantRole.TenantRoleChoices.TENANT_ADMIN.label,
            role_type=TenantRole.TenantRoleChoices.TENANT_ADMIN,  # Assuming ADMIN = 2
        )

        # Assign all PermissionChoices to the role
        for choice in TenantPermissionChoices:
            TenantRolePermissions.objects.create(role=role, permission=choice.value)

        return tenant
