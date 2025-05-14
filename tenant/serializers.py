# tenant/serializers.py
from django.db import transaction
from loguru import logger
from rest_framework import serializers

from authentication.models import User
from integration.models import Integration

from .models import (
    DuIbmQradarTenants,
    DuITSMTenants,
    IBMQradarEventCollector,
    Tenant,
    TenantPermissionChoices,
    TenantQradarMapping,
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
#     email = serializers.EmailField(write_only=True)
#     username = serializers.CharField(write_only=True)
#     name = serializers.CharField(write_only=True)
#     password = serializers.CharField(write_only=True, style={"input_type": "password"})
#     qradar_tenant_id = serializers.IntegerField(required=False, allow_null=True)
#     event_collector_id = serializers.IntegerField(required=False, allow_null=True)
#     integration_id = serializers.IntegerField(required=False, allow_null=True)
#     role_permissions = serializers.ListField(
#         child=serializers.IntegerField(), required=False, write_only=True
#     )

#     class Meta:
#         model = Tenant
#         fields = [
#             "email",
#             "username",
#             "name",
#             "password",
#             "phone_number",
#             "country",
#             "qradar_tenant_id",
#             "event_collector_id",
#             "integration_id",
#             "role_permissions",
#             "id",
#             "created_at",
#             "updated_at",
#         ]
#         read_only_fields = ["id", "created_at", "updated_at"]

#     def validate(self, data):
#         # Validate role_permissions
#         if "role_permissions" in data:
#             valid_permissions = [
#                 choice[0] for choice in TenantPermissionChoices.choices
#             ]
#             for perm in data["role_permissions"]:
#                 if perm not in valid_permissions:
#                     raise serializers.ValidationError(
#                         {"role_permissions": f"Invalid permission value: {perm}"}
#                     )
#         return data

#     def create(self, validated_data):
#         with transaction.atomic():
#             # Extract user data
#             user_data = {
#                 "email": validated_data.pop("email"),
#                 "username": validated_data.pop("username"),
#                 "name": validated_data.pop("name"),
#                 "password": validated_data.pop("password"),
#             }
#             role_permissions = validated_data.pop("role_permissions", [])

#             # Create User
#             if User.objects.filter(email=user_data["email"]).exists():
#                 raise serializers.ValidationError(
#                     {"email": "User with this email already exists"}
#                 )
#             if User.objects.filter(username=user_data["username"]).exists():
#                 raise serializers.ValidationError(
#                     {"username": "User with this username already exists"}
#                 )

#             user = User(
#                 email=user_data["email"],
#                 username=user_data["username"],
#                 name=user_data["name"],
#                 is_tenant=True,
#                 is_active=True,
#             )
#             user.set_password(user_data["password"])
#             user.save()

#             # Get created_by from request user
#             created_by = self.context["request"].user

#             # Handle qradar_tenant
#             qradar_tenant = None
#             if validated_data.get("qradar_tenant_id"):
#                 try:
#                     qradar_tenant = DuIbmQradarTenants.objects.get(
#                         id=validated_data.pop("qradar_tenant_id")
#                     )
#                 except DuIbmQradarTenants.DoesNotExist:
#                     raise serializers.ValidationError(
#                         {"qradar_tenant_id": "Invalid qradar_tenant_id"}
#                     )

#             # Handle event_collector
#             event_collector = None
#             if validated_data.get("event_collector_id"):
#                 try:
#                     event_collector = IBMQradarEventCollector.objects.get(
#                         id=validated_data.pop("event_collector_id")
#                     )
#                 except IBMQradarEventCollector.DoesNotExist:
#                     raise serializers.ValidationError(
#                         {"event_collector_id": "Invalid event_collector_id"}
#                     )

#             # Handle integration
#             integration = None
#             if validated_data.get("integration_id"):
#                 try:
#                     integration = Integration.objects.get(
#                         id=validated_data.pop("integration_id")
#                     )
#                 except Integration.DoesNotExist:
#                     raise serializers.ValidationError(
#                         {"integration_id": "Invalid integration_id"}
#                     )

#             # Create Tenant
#             tenant = Tenant.objects.create(
#                 tenant=user,
#                 created_by=created_by,
#                 integration=integration,
#                 qradar_tenant=qradar_tenant,
#                 event_collector=event_collector,
#                 **validated_data,
#             )

#             # Create TenantRole
#             role = TenantRole.objects.create(
#                 tenant=tenant,
#                 name="Tenant Admin",
#                 role_type=TenantRole.TenantRoleChoices.TENANT_ADMIN,
#             )

#             # Create TenantRolePermissions
#             for permission in role_permissions:
#                 TenantRolePermissions.objects.create(role=role, permission=permission)

#             return tenant


class QradarTenantInputSerializer(serializers.Serializer):
    qradar_tenant_id = serializers.IntegerField()
    event_collector_ids = serializers.ListField(
        child=serializers.IntegerField(), required=False, default=[]
    )


class TenantCreateSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(write_only=True)
    username = serializers.CharField(write_only=True)
    name = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True, style={"input_type": "password"})
    qradar_tenants = QradarTenantInputSerializer(
        many=True, required=False, write_only=True
    )
    integration_ids = serializers.ListField(
        child=serializers.IntegerField(), required=False, write_only=True
    )
    itsm_tenant_ids = serializers.ListField(
        child=serializers.IntegerField(), required=False, write_only=True
    )
    role_permissions = serializers.ListField(
        child=serializers.IntegerField(), required=False, write_only=True
    )
    is_itsm_tenant = serializers.BooleanField(default=False, write_only=True)

    class Meta:
        model = Tenant
        fields = [
            "email",
            "username",
            "name",
            "password",
            "phone_number",
            "country",
            "qradar_tenants",
            "integration_ids",
            "itsm_tenant_ids",
            "role_permissions",
            "is_itsm_tenant",
            "id",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def validate(self, data):
        logger.debug("Starting validation with data: %s", data)
        if "integration_ids" in data and len(data["integration_ids"]) == 0:
            raise serializers.ValidationError(
                {"integration_ids": "At least one integration is required"}
            )
        if (
            "qradar_tenants" in data
            and len(data["qradar_tenants"]) == 0
            and "itsm_tenant_ids"
            and len(data["itsm_tenant_ids"]) == 0
        ):
            raise serializers.ValidationError(
                {
                    "qradar_tenants": "At least one qradar tenant or itsm tenant is required"
                }
            )
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

        # Validate qradar_tenants
        if "qradar_tenants" in data:
            qradar_tenant_ids = [
                qt["qradar_tenant_id"] for qt in data["qradar_tenants"]
            ]
            if len(qradar_tenant_ids) != len(set(qradar_tenant_ids)):
                raise serializers.ValidationError(
                    {"qradar_tenants": "Duplicate qradar_tenant_ids are not allowed"}
                )

            # Validate qradar_tenant_ids and event_collector_ids
            all_event_collector_ids = []
            for qt in data["qradar_tenants"]:
                # Check qradar_tenant_id
                if not DuIbmQradarTenants.objects.filter(
                    id=qt["qradar_tenant_id"]
                ).exists():
                    raise serializers.ValidationError(
                        {
                            "qradar_tenants": f"Invalid qradar_tenant_id: {qt['qradar_tenant_id']}"
                        }
                    )
                # Check event_collector_ids
                event_collector_ids = qt["event_collector_ids"]
                if event_collector_ids:
                    valid_event_collectors = IBMQradarEventCollector.objects.filter(
                        id__in=event_collector_ids
                    )
                    if len(valid_event_collectors) != len(event_collector_ids):
                        invalid_ids = set(event_collector_ids) - set(
                            ec.id for ec in valid_event_collectors
                        )
                        raise serializers.ValidationError(
                            {
                                "qradar_tenants": f"Invalid event_collector_ids: {invalid_ids} for qradar_tenant_id: {qt['qradar_tenant_id']}"
                            }
                        )
                    all_event_collector_ids.extend(event_collector_ids)

            # Ensure no duplicate event_collector_ids across qradar_tenants
            if len(all_event_collector_ids) != len(set(all_event_collector_ids)):
                raise serializers.ValidationError(
                    {
                        "qradar_tenants": "Duplicate event_collector_ids across qradar_tenants are not allowed"
                    }
                )

        # Validate integration_ids
        if "integration_ids" in data:
            integrations = Integration.objects.filter(id__in=data["integration_ids"])
            if len(integrations) != len(data["integration_ids"]):
                invalid_ids = set(data["integration_ids"]) - set(
                    intg.id for intg in integrations
                )
                raise serializers.ValidationError(
                    {"integration_ids": f"Invalid integration_ids: {invalid_ids}"}
                )

        # Validate itsm_tenant_ids and integration_ids consistency
        if "itsm_tenant_ids" in data and data.get("is_itsm_tenant") is False:
            raise serializers.ValidationError(
                {
                    "itsm_tenant_ids": "is_itsm_tenant must be true when itsm_tenant_ids are provided"
                }
            )

        if "itsm_tenant_ids" in data:
            itsm_tenants = DuITSMTenants.objects.filter(
                id__in=data["itsm_tenant_ids"]
            ).select_related("integration")
            if len(itsm_tenants) != len(data["itsm_tenant_ids"]):
                invalid_ids = set(data["itsm_tenant_ids"]) - set(
                    itsm.id for itsm in itsm_tenants
                )
                raise serializers.ValidationError(
                    {"itsm_tenant_ids": f"Invalid itsm_tenant_ids: {invalid_ids}"}
                )
            if "integration_ids" in data:
                for itsm_tenant in itsm_tenants:
                    if (
                        itsm_tenant.integration
                        and itsm_tenant.integration.id not in data["integration_ids"]
                    ):
                        raise serializers.ValidationError(
                            {
                                "itsm_tenant_ids": f"ITSM tenant {itsm_tenant.id} is linked to integration {itsm_tenant.integration.id}, which is not included in integration_ids"
                            }
                        )

        logger.debug("Validation passed")
        return data

    def create(self, validated_data):
        logger.debug("Starting tenant creation with validated_data: %s", validated_data)

        with transaction.atomic():
            # Extract user data
            user_data = {
                "email": validated_data.pop("email"),
                "username": validated_data.pop("username"),
                "name": validated_data.pop("name"),
                "password": validated_data.pop("password"),
            }
            role_permissions = validated_data.pop("role_permissions", [])
            integration_ids = validated_data.pop("integration_ids", [])
            qradar_tenants_data = validated_data.pop("qradar_tenants", [])
            itsm_tenant_ids = validated_data.pop("itsm_tenant_ids", [])
            is_itsm_tenant = validated_data.pop("is_itsm_tenant", False)

            # Create User
            logger.debug("Checking for existing user")
            if User.objects.filter(email=user_data["email"]).exists():
                raise serializers.ValidationError(
                    {"email": "User with this email already exists"}
                )
            if User.objects.filter(username=user_data["username"]).exists():
                raise serializers.ValidationError(
                    {"username": "User with this username already exists"}
                )

            logger.debug("Creating user")
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
            logger.debug("Created by: %s", created_by)

            # Create Tenant
            logger.debug("Creating tenant")
            tenant = Tenant.objects.create(
                tenant=user,
                created_by=created_by,
                is_itsm_tenant=is_itsm_tenant,
                **validated_data,
            )

            # Handle qradar_tenants and event_collectors
            all_event_collectors = []
            for qt_data in qradar_tenants_data:
                logger.debug("Processing qradar_tenant: %s", qt_data)
                qradar_tenant = DuIbmQradarTenants.objects.get(
                    id=qt_data["qradar_tenant_id"]
                )  # Already validated
                event_collectors = []
                for ec_id in qt_data["event_collector_ids"]:
                    ec = IBMQradarEventCollector.objects.get(
                        id=ec_id
                    )  # Already validated
                    event_collectors.append(ec)
                    if ec not in all_event_collectors:
                        all_event_collectors.append(ec)

                # Create mapping
                mapping = TenantQradarMapping.objects.create(
                    tenant=tenant, qradar_tenant=qradar_tenant
                )
                mapping.event_collectors.set(event_collectors)

            # Handle itsm_tenants
            itsm_tenants = []
            if itsm_tenant_ids:
                logger.debug("Processing itsm_tenant_ids: %s", itsm_tenant_ids)
                for itsm_id in itsm_tenant_ids:
                    itsm_tenant = DuITSMTenants.objects.get(
                        id=itsm_id
                    )  # Already validated
                    itsm_tenants.append(itsm_tenant)
                tenant.itsm_tenants.set(itsm_tenants)

            # Handle integrations
            integrations = []
            if integration_ids:
                logger.debug("Processing integration_ids: %s", integration_ids)
                for int_id in integration_ids:
                    integration = Integration.objects.get(
                        id=int_id
                    )  # Already validated
                    integrations.append(integration)
                tenant.integrations.set(integrations)

            # Associate all event collectors with tenant
            if all_event_collectors:
                logger.debug("Associating event collectors: %s", all_event_collectors)
                tenant.event_collectors.set(all_event_collectors)

            # Create TenantRole
            logger.debug("Creating tenant role")
            role = TenantRole.objects.create(
                tenant=tenant,
                name="Tenant Admin",
                role_type=TenantRole.TenantRoleChoices.TENANT_ADMIN,
            )

            # Create TenantRolePermissions
            for permission in role_permissions:
                logger.debug("Creating role permission: %s", permission)
                TenantRolePermissions.objects.create(role=role, permission=permission)

            logger.debug("Tenant creation completed successfully")
            return tenant


class DuIbmQradarTenantsSerializer(serializers.ModelSerializer):
    class Meta:
        model = DuIbmQradarTenants
        fields = ["id", "name"]


class IBMQradarEventCollectorSerializer(serializers.Serializer):
    event_collector_id = serializers.IntegerField(source="id", read_only=True)
    name = serializers.CharField(max_length=255, allow_blank=True, default="")
    host_id = serializers.IntegerField()
    component_name = serializers.CharField(max_length=255, allow_blank=True, default="")

    class Meta:
        model = IBMQradarEventCollector
        fields = ["event_collector_id", "name", "host_id", "component_name"]


class DuITSMTenantsSerializer(serializers.ModelSerializer):
    class Meta:
        model = DuITSMTenants
        fields = ["id", "name"]
