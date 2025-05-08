# tenant/serializers.py
from django.db import transaction
from loguru import logger
from rest_framework import serializers

from authentication.models import User
from integration.models import Integration

from .models import (
    DuIbmQradarTenants,
    IBMQradarEventCollector,
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
    tenant_admin = serializers.SerializerMethodField()
    asset_count = serializers.SerializerMethodField()
    total_incidents = serializers.SerializerMethodField()
    active_incidents = serializers.SerializerMethodField()
    tickets_count = serializers.SerializerMethodField()
    sla = serializers.SerializerMethodField()

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
            "asset_count",
            "total_incidents",
            "active_incidents",
            "tickets_count",
            "sla",
            "tenant_admin",
        ]

    def get_permissions(self, obj):
        try:
            role = obj.roles.get()
            return [
                {"id": perm.permission, "name": perm.permission_text}
                for perm in role.role_permissions.all()
            ]
        except Exception as e:
            logger.error(e)
            return []

    def get_tenant_admin(self, obj):
        if obj.tenant:
            return obj.created_by.username or None
        return None

    def get_asset_count(self, obj):
        try:
            return obj.asset_set.count()
        except Exception:
            return 2

    def get_total_incidents(self, obj):
        try:
            return obj.incident_set.count()
        except Exception:
            return 0

    def get_active_incidents(self, obj):
        try:
            return obj.incident_set.filter(status="active").count()
        except Exception:
            return 0

    def get_tickets_count(self, obj):
        try:
            return obj.ticket_set.count()
        except Exception:
            return 0

    def get_sla(self, obj):
        try:
            return obj.sla.name
        except Exception:
            return 0


# class TenantDetailSerializer(serializers.ModelSerializer):
#     username = serializers.CharField(source="tenant.username", read_only=True)
#     email = serializers.EmailField(source="tenant.email", read_only=True)
#     permissions = serializers.SerializerMethodField()
#     # tenant_admin = serializers.SerializerMethodField()
#     # assert_count = serializers.SerializerMethodField()
#     # total_incidents = serializers.SerializerMethodField()
#     # active_incidents = serializers.SerializerMethodField()
#     tickets_count = serializers.SerializerMethodField()
#     sla = serializers.SerializerMethodField()
#     class Meta:
#         model = Tenant
#         fields = [
#             "id",
#             "username",
#             "email",
#             "phone_number",
#             "total_incidents",
#             # "active_incidents",
#             "tickets_count",
#             "sla",
#             # "tenant_admin",
#             "created_at",
#             "updated_at",
#             "permissions",
#         ]

#     def get_permissions(self, obj):
#         try:
#             role = obj.roles.get()  # Assumes one role per tenant
#             return [
#                 {"id": perm.permission, "name": perm.permission_text}
#                 for perm in role.role_permissions.all()
#             ]
#         except TenantRole.DoesNotExist:
#             return []

#     # def get_tenant_admin(self, obj):
#     #     return obj.tenant.get_full_name()  # Assuming `tenant` is a User with first_name and last_name

#     # def get_assert_count(self, obj):
#     #     # Replace with actual logic to count tenant's assets
#     #     return obj.assets.count() if hasattr(obj, "assets") else 0

#     def get_total_incidents(self, obj):
#         return 0 #obj.incidents.count() if hasattr(obj, "incidents") else 0

#     # def get_active_incidents(self, obj):
#     #     return 0

#     def get_tickets_count(self, obj):
#         return obj.tickets.count() if hasattr(obj, "tickets") else 0

#     def get_sla(self, obj):
#         return obj.sla.name if hasattr(obj, "sla") and obj.sla else None


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


# class TenantCreateSerializer(serializers.ModelSerializer):
#     username = serializers.CharField(max_length=100, write_only=True)
#     email = serializers.EmailField(write_only=True)
#     password = serializers.CharField(write_only=True, style={"input_type": "password"})
#     phone_number = serializers.CharField(
#         max_length=20, required=False, allow_blank=True
#     )
#     permissions = serializers.ListField(
#         child=serializers.IntegerField(min_value=1, max_value=5),
#         required=False,
#         help_text="List of permission integers from TenantPermissionChoices (1-5)",
#     )
#     qradar_tenant_id = serializers.IntegerField(
#         required=True, help_text="ID of the associated DuIbmQradarTenants"
#     )

#     def validate_username(self, value):
#         if User.objects.filter(username=value).exists():
#             raise serializers.ValidationError(
#                 f"A user with the username '{value}' already exists."
#             )
#         return value

#     def validate_email(self, value):
#         if User.objects.filter(email=value).exists():
#             raise serializers.ValidationError(
#                 f"A user with the email '{value}' already exists."
#             )
#         return value

#     def validate_permissions(self, value):
#         valid_choices = [choice.value for choice in TenantPermissionChoices]
#         if value:
#             invalid = [p for p in value if p not in valid_choices]
#             if invalid:
#                 raise serializers.ValidationError(
#                     f"Invalid permissions: {invalid}. Must be one of {valid_choices}"
#                 )
#         return value

#     def validate_qradar_tenant_id(self, value):
#         # Check if the qradar_tenant_id exists
#         if not DuIbmQradarTenants.objects.filter(id=value).exists():
#             raise serializers.ValidationError(
#                 f"No DuIbmQradarTenants found with ID {value}"
#             )
#         # Check if a tenant already exists with this qradar_tenant_id
#         if Tenant.objects.filter(qradar_tenant__id=value).exists():
#             raise serializers.ValidationError(
#                 f"A tenant already exists for DuIbmQradarTenants ID {value}"
#             )
#         return value

#     def validate(self, data):
#         integration_type = data.get("integration_type")
#         siem_subtype = data.get("siem_subtype")
#         soar_subtype = data.get("soar_subtype")
#         itsm_subtype = data.get("itsm_subtype")

#         if integration_type == IntegrationTypes.SIEM_INTEGRATION:
#             if not siem_subtype:
#                 raise serializers.ValidationError(
#                     {
#                         "siem_subtype": "SIEM subtype is required for SIEM Integration type."
#                     }
#                 )
#         elif integration_type == IntegrationTypes.SOAR_INTEGRATION:
#             if not soar_subtype:
#                 raise serializers.ValidationError(
#                     {
#                         "soar_subtype": "SOAR subtype is required for SOAR Integration type."
#                     }
#                 )
#         elif integration_type == IntegrationTypes.ITSM_INTEGRATION:
#             if not itsm_subtype:
#                 raise serializers.ValidationError(
#                     {
#                         "itsm_subtype": "ITSM subtype is required for ITSM Integration type."
#                     }
#                 )
#         return data

#     def create(self, validated_data):
#         permissions = validated_data.pop("permissions", [])
#         integration_type = validated_data.pop("integration_type")
#         siem_subtype = validated_data.pop("siem_subtype", None)
#         soar_subtype = validated_data.pop("soar_subtype", None)
#         itsm_subtype = validated_data.pop("itsm_subtype", None)
#         instance_name = validated_data.pop("instance_name")
#         instance_type = validated_data.pop("instance_type")
#         api_key = validated_data.pop("api_key")
#         version = validated_data.pop("version")
#         qradar_tenant_id = validated_data.pop("qradar_tenant_id")

#         user_data = {
#             "username": validated_data.pop("username"),
#             "email": validated_data.pop("email"),
#             "is_tenant": True,
#         }
#         raw_password = validated_data.pop("password")
#         phone_number = validated_data.pop("phone_number", None)

#         # Create User instance
#         user = User(**user_data)
#         user.set_password(raw_password)
#         user.save()

#         # Get qradar tenant
#         qradar_tenant = DuIbmQradarTenants.objects.get(id=qradar_tenant_id)

#         # Create Tenant instance
#         tenant = Tenant(
#             tenant=user,
#             created_by=self.context["request"].user,
#             phone_number=phone_number,
#             qradar_tenant=qradar_tenant,
#         )
#         tenant.save()

#         # Create TenantRole
#         role = TenantRole.objects.create(
#             tenant=tenant,
#             name=f"{user.username} Admin",
#             role_type=TenantRole.TenantRoleChoices.TENANT_ADMIN,
#         )

#         # Assign permissions
#         for perm_value in permissions:
#             TenantRolePermissions.objects.create(role=role, permission=perm_value)

#         # Create Integration
#         integration = Integration(
#             tenant=tenant,
#             integration_type=integration_type,
#             siem_subtype=siem_subtype,
#             soar_subtype=soar_subtype,
#             itsm_subtype=itsm_subtype,
#             instance_name=instance_name,
#             instance_type=instance_type,
#             api_key=api_key,
#             version=version,
#         )
#         integration.save()

#         return tenant


class TenantCreateSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(write_only=True)
    username = serializers.CharField(write_only=True)
    name = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True, style={"input_type": "password"})
    qradar_tenant_id = serializers.IntegerField(required=False, allow_null=True)
    event_collector_id = serializers.IntegerField(required=False, allow_null=True)
    integration_id = serializers.IntegerField(required=False, allow_null=True)
    role_permissions = serializers.ListField(
        child=serializers.IntegerField(), required=False, write_only=True
    )

    class Meta:
        model = Tenant
        fields = [
            "email",
            "username",
            "name",
            "password",
            "phone_number",
            "country",
            "qradar_tenant_id",
            "event_collector_id",
            "integration_id",
            "role_permissions",
            "id",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def validate(self, data):
        # Validate role_permissions
        if "role_permissions" in data:
            valid_permissions = [
                choice[0] for choice in TenantPermissionChoices.choices
            ]
            for perm in data["role_permissions"]:
                if perm not in valid_permissions:
                    raise serializers.ValidationError(
                        {"role_permissions": f"Invalid permission value: {perm}"}
                    )
        return data

    def create(self, validated_data):
        with transaction.atomic():
            # Extract user data
            user_data = {
                "email": validated_data.pop("email"),
                "username": validated_data.pop("username"),
                "name": validated_data.pop("name"),
                "password": validated_data.pop("password"),
            }
            role_permissions = validated_data.pop("role_permissions", [])

            # Create User
            if User.objects.filter(email=user_data["email"]).exists():
                raise serializers.ValidationError(
                    {"email": "User with this email already exists"}
                )
            if User.objects.filter(username=user_data["username"]).exists():
                raise serializers.ValidationError(
                    {"username": "User with this username already exists"}
                )

            user = User(
                email=user_data["email"],
                username=user_data["username"],
                name=user_data["name"],
                is_tenant=True,
                is_active=True,
            )
            user.set_password(user_data["password"])
            user.save()

            # Get created_by from request user
            created_by = self.context["request"].user

            # Handle qradar_tenant
            qradar_tenant = None
            if validated_data.get("qradar_tenant_id"):
                try:
                    qradar_tenant = DuIbmQradarTenants.objects.get(
                        id=validated_data.pop("qradar_tenant_id")
                    )
                except DuIbmQradarTenants.DoesNotExist:
                    raise serializers.ValidationError(
                        {"qradar_tenant_id": "Invalid qradar_tenant_id"}
                    )

            # Handle event_collector
            event_collector = None
            if validated_data.get("event_collector_id"):
                try:
                    event_collector = IBMQradarEventCollector.objects.get(
                        id=validated_data.pop("event_collector_id")
                    )
                except IBMQradarEventCollector.DoesNotExist:
                    raise serializers.ValidationError(
                        {"event_collector_id": "Invalid event_collector_id"}
                    )

            # Handle integration
            integration = None
            if validated_data.get("integration_id"):
                try:
                    integration = Integration.objects.get(
                        id=validated_data.pop("integration_id")
                    )
                except Integration.DoesNotExist:
                    raise serializers.ValidationError(
                        {"integration_id": "Invalid integration_id"}
                    )

            # Create Tenant
            tenant = Tenant.objects.create(
                tenant=user,
                created_by=created_by,
                integration=integration,
                qradar_tenant=qradar_tenant,
                event_collector=event_collector,
                **validated_data,
            )

            # Create TenantRole
            role = TenantRole.objects.create(
                tenant=tenant,
                name="Tenant Admin",
                role_type=TenantRole.TenantRoleChoices.TENANT_ADMIN,
            )

            # Create TenantRolePermissions
            for permission in role_permissions:
                TenantRolePermissions.objects.create(role=role, permission=permission)

            return tenant


class DuIbmQradarTenantsSerializer(serializers.ModelSerializer):
    qradar_tenant_id = serializers.IntegerField(source="id", read_only=True)

    class Meta:
        model = DuIbmQradarTenants
        fields = ["qradar_tenant_id", "name"]


class IBMQradarEventCollectorSerializer(serializers.Serializer):
    event_collector_id = serializers.IntegerField(source="id", read_only=True)
    name = serializers.CharField(max_length=255, allow_blank=True, default="")
    host_id = serializers.IntegerField()
    component_name = serializers.CharField(max_length=255, allow_blank=True, default="")

    class Meta:
        model = IBMQradarEventCollector
        fields = ["event_collector_id", "name", "host_id", "component_name"]
