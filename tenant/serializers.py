# tenant/serializers.py
from rest_framework import serializers

from authentication.models import User

from .models import Tenant, TenantPermissionChoices, TenantRole, TenantRolePermissions


class TenantCreateSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=100, write_only=True)  # Replaces name
    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(write_only=True, style={"input_type": "password"})
    phone_number = serializers.CharField(
        max_length=20, required=False, allow_blank=True
    )
    permissions = serializers.ListField(
        child=serializers.IntegerField(min_value=1, max_value=5),
        required=False,
        help_text="List of permission integers from TenantPermissionChoices (1-5) to assign to the tenant",
    )

    class Meta:
        model = Tenant
        fields = ["username", "email", "password", "phone_number", "permissions"]

    def validate_username(self, value):
        """Check if a user with this username already exists."""
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError(
                f"A user with the username '{value}' already exists."
            )
        return value

    def validate_email(self, value):
        """Check if a user with this email already exists."""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                f"A user with the email '{value}' already exists."
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

        # Create Tenant instance
        tenant = Tenant(
            tenant=user,
            created_by=self.context["request"].user,
            phone_number=phone_number,
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

        return tenant


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
