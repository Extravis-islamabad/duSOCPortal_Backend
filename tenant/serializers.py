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


class TenantUpdateSerializer(serializers.ModelSerializer):
    permissions = serializers.ListField(
        child=serializers.IntegerField(min_value=1, max_value=5),
        required=False,
        help_text="List of permission integers from TenantPermissionChoices (1-5) to assign to the tenant",
    )

    class Meta:
        model = Tenant
        fields = ["name", "password", "email", "phone_number", "permissions"]
        extra_kwargs = {
            "name": {"required": False},
            "password": {"required": False},
            "email": {"required": False},
            "phone_number": {"required": False},
        }

    def validate_name(self, value):
        """Check if a tenant with this name already exists, excluding the current instance."""
        tenant = self.instance
        if value and Tenant.objects.filter(name=value).exclude(id=tenant.id).exists():
            raise serializers.ValidationError(
                f"A tenant with the name '{value}' already exists."
            )
        return value

    def validate_email(self, value):
        """Check if a tenant with this email already exists, excluding the current instance."""
        tenant = self.instance
        if value and Tenant.objects.filter(email=value).exclude(id=tenant.id).exists():
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

    def update(self, instance, validated_data):
        # Extract permissions (if provided)
        permissions = validated_data.pop("permissions", None)

        # Update only provided fields
        if "name" in validated_data:
            instance.name = validated_data["name"]
        if "password" in validated_data:
            raw_password = validated_data["password"]
            if raw_password is not None:  # Allow nulling the password
                if raw_password:
                    instance.set_password(raw_password)
                else:
                    instance.password = None
        if "email" in validated_data:
            instance.email = validated_data["email"]
        if "phone_number" in validated_data:
            instance.phone_number = validated_data["phone_number"]
        instance.save()

        # Update permissions only if provided
        if permissions is not None:
            # Get or create the tenant's role (assuming one role per tenant)
            role, _ = TenantRole.objects.get_or_create(
                tenant=instance,
                defaults={
                    "name": f"{instance.name or 'Tenant'} Admin",
                    "role_type": TenantRole.TenantRoleChoices.TENANT_ADMIN,
                },
            )
            # Clear existing permissions
            TenantRolePermissions.objects.filter(role=role).delete()
            # Add new permissions
            for perm_value in permissions:
                TenantRolePermissions.objects.create(role=role, permission=perm_value)

        return instance
