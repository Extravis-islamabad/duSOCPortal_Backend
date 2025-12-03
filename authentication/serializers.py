from rest_framework import serializers
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken

from common.constants import RedirectionURLConstant
from tenant.models import Tenant, TenantRole, TenantRolePermissions

from .models import User, UserPreferences


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
    integrated_tools = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "name",
            "profile_picture",
            "is_tenant",
            "is_super_admin",
            "is_admin",
            "is_read_only",
            "company_name",
            "created_at",
            "updated_at",
            "company_name",
            "permissions",
            "created_by_id",
            "integrated_tools",
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
        """
        Returns the URL of the profile picture associated with the tenant if it exists.
        For admins (or non-tenants), returns None.
        """
        if obj.is_tenant:
            tenant = Tenant.objects.filter(tenant=obj).first()
            if tenant and tenant.company and tenant.company.profile_picture:
                return f"{RedirectionURLConstant.PUBLIC_DOMAIN}{tenant.company.profile_picture.url}"
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

    def get_integrated_tools(self, obj):
        """
        Returns the list of integrated tools for tenants or an empty list/null for admins.
        """
        if obj.is_tenant:
            try:
                # Fetch the tenant profile associated with the user
                tenant = Tenant.objects.get(tenant=obj)
                # Get the company associated with the tenant
                if tenant.company:
                    # Get all integrations for the company
                    integrations = tenant.company.integrations.filter(status=True)
                    # Format the integration data
                    integrated_tools = []
                    for integration in integrations:
                        tool_data = {
                            "id": integration.id,
                            "instance_name": integration.instance_name,
                            "integration_type": integration.get_integration_type_display(),
                            "status": integration.status,
                        }

                        # Add the specific subtype based on integration type
                        if integration.integration_type == 1:  # SIEM
                            tool_data["subtype"] = (
                                integration.get_siem_subtype_display()
                                if integration.siem_subtype
                                else None
                            )
                        elif integration.integration_type == 2:  # SOAR
                            tool_data["subtype"] = (
                                integration.get_soar_subtype_display()
                                if integration.soar_subtype
                                else None
                            )
                        elif integration.integration_type == 3:  # ITSM
                            tool_data["subtype"] = (
                                integration.get_itsm_subtype_display()
                                if integration.itsm_subtype
                                else None
                            )
                        elif integration.integration_type == 4:  # Threat Intelligence
                            tool_data["subtype"] = (
                                integration.get_threat_intelligence_subtype_display()
                                if integration.threat_intelligence_subtype
                                else None
                            )
                        else:
                            tool_data["subtype"] = None

                        integrated_tools.append(tool_data)

                    return integrated_tools
            except Tenant.DoesNotExist:
                # If no tenant profile exists, return an empty list
                return []
        # For admins (or non-tenants), return an empty list
        return []


class ProfilePictureUploadSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["profile_picture", "company_name"]


class UserPreferencesSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserPreferences
        fields = ["data", "updated_at"]
        read_only_fields = ["updated_at"]


class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        from django.contrib.auth import get_user_model

        self.refresh = attrs["refresh"]

        try:
            refresh = RefreshToken(self.refresh)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        # Check if the user associated with the token still exists
        User = get_user_model()
        user_id = refresh.get("user_id")

        if user_id:
            try:
                user = User.objects.get(id=user_id, is_active=True, is_deleted=False)
            except User.DoesNotExist:
                raise InvalidToken("User no longer exists or is inactive")
        else:
            raise InvalidToken("Invalid token: no user_id")

        data = {}
        data["access"] = str(refresh.access_token)

        if api_settings.ROTATE_REFRESH_TOKENS:
            refresh.blacklist()  # blacklist the old one
            new_refresh = RefreshToken.for_user(user)
            data["refresh"] = str(new_refresh)

        return data
