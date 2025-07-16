from rest_framework import serializers
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken

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
    profile_picture = serializers.SerializerMethodField()
    company_name = serializers.SerializerMethodField()
    created_by_id = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "name",
            "profile_picture",
            "is_tenant",
            "is_admin",
            "company_name",
            "created_at",
            "updated_at",
            "company_name",
            "permissions",
            "created_by_id",
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

    def get_profile_picture(self, obj):
        if obj.is_tenant:
            tenant = Tenant.objects.filter(tenant=obj).first()
            if tenant and tenant.company and tenant.company.profile_picture:
                request = self.context.get("request")
                return request.build_absolute_uri(tenant.company.profile_picture.url)
        return None

    def get_company_name(self, obj):
        if obj.is_tenant:
            tenant = Tenant.objects.filter(tenant=obj).first()
            return tenant.company.company_name if tenant else None
        return None

    def get_created_by_id(self, obj):
        """
        Returns the ID of the admin who created the tenant, or None for admins.
        """
        if obj.is_tenant:
            tenant = Tenant.objects.filter(tenant=obj).first()
            if tenant and tenant.created_by:
                return tenant.created_by.id
        return None


class ProfilePictureUploadSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["profile_picture", "company_name"]


class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        self.refresh = attrs["refresh"]

        try:
            refresh = RefreshToken(self.refresh)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        data = {}
        data["access"] = str(refresh.access_token)

        if api_settings.ROTATE_REFRESH_TOKENS:
            refresh.blacklist()  # blacklist the old one
            new_refresh = RefreshToken.for_user(self.context["request"].user)
            data["refresh"] = str(new_refresh)

        return data
