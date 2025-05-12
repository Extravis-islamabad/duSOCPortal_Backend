from rest_framework import serializers

from tenant.models import Tenant, TenantRole, TenantRolePermissions

from .models import User


class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    is_admin = serializers.BooleanField(default=True)

    class Meta:
        model = User
        fields = ["username", "email", "name", "password", "is_super_admin", "is_admin"]

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user


class UserDetailSerializer(serializers.ModelSerializer):
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "name",
            "is_tenant",
            "is_admin",
            "created_at",
            "updated_at",
            "permissions",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def get_permissions(self, obj):
        """
        Returns the list of permissions for tenants or an empty list for admins.
        """
        if obj.is_tenant:
            try:
                # Fetch the tenant profile associated with the user
                tenant = Tenant.objects.get(tenant=obj)
                # Fetch the tenant's role
                tenant_role = TenantRole.objects.filter(tenant=tenant).first()
                if tenant_role:
                    # Fetch all permissions associated with the role
                    role_permissions = TenantRolePermissions.objects.filter(
                        role=tenant_role
                    )
                    # Return permissions as a list of dictionaries
                    return [
                        {
                            "id": perm.permission,
                            "name": perm.permission_text,
                        }
                        for perm in role_permissions
                    ]
            except Tenant.DoesNotExist:
                # If no tenant profile exists, return an empty list
                return []
        # For admins (or non-tenants), return an empty list
        return []
