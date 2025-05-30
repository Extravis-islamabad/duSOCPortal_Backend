# tenant/serializers.py
from django.db import transaction
from django.db.models import Count
from loguru import logger
from rest_framework import serializers

from authentication.models import User
from integration.models import Integration

from .models import (
    DUCortexSOARIncidentFinalModel,
    DuCortexSOARTenants,
    DuIbmQradarTenants,
    DuITSMFinalTickets,
    DuITSMTenants,
    IBMQradarAssests,
    IBMQradarEPS,
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
    total_incidents = serializers.SerializerMethodField()
    active_incidents = serializers.SerializerMethodField()
    tickets_count = serializers.SerializerMethodField()
    sla = serializers.SerializerMethodField()
    asset_count = serializers.SerializerMethodField()

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
            # Get all event collector IDs for the tenant
            collector_ids = TenantQradarMapping.objects.filter(tenant=obj).values_list(
                "event_collectors__id", flat=True
            )

            # Count assets for these collectors
            asset_count = IBMQradarAssests.objects.filter(
                event_collector__id__in=collector_ids
            ).aggregate(totalAssets=Count("id"))

            return asset_count["totalAssets"] or 0
        except Exception:
            return 0

    def get_active_incidents(self, obj):
        return self.get_total_incidents(obj)

    def get_sla(self, obj):
        try:
            return obj.sla.name
        except Exception:
            return 0

    def get_total_incidents(self, obj):
        try:
            soar_tenants = obj.soar_tenants.all()
            return DUCortexSOARIncidentFinalModel.objects.filter(
                cortex_soar_tenant__in=soar_tenants
            ).count()
        except Exception:
            return 0

    def get_tickets_count(self, obj):
        try:
            itsm_tenants = obj.itsm_tenants.all()
            return DuITSMFinalTickets.objects.filter(
                itsm_tenant__in=itsm_tenants
            ).count()
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
    soar_tenant_ids = serializers.ListField(
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
            "qradar_tenants",
            "integration_ids",
            "itsm_tenant_ids",
            "soar_tenant_ids",
            "role_permissions",
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
            and "soar_tenant_ids" in data
            and len(data["soar_tenant_ids"]) == 0
        ):
            raise serializers.ValidationError(
                {
                    "error": "At least one qradar tenant or itsm tenant or soar tenant is required"
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

        if "soar_tenant_ids" in data:
            soar_tenants = DuCortexSOARTenants.objects.filter(
                id__in=data["soar_tenant_ids"]
            ).select_related("integration")
            if len(soar_tenants) != len(data["soar_tenant_ids"]):
                invalid_ids = set(data["soar_tenant_ids"]) - set(
                    itsm.id for itsm in soar_tenants
                )
                raise serializers.ValidationError(
                    {"soar_tenant_ids": f"Invalid soar_tenant_ids: {invalid_ids}"}
                )
            if "integration_ids" in data:
                for soar_tenant in soar_tenants:
                    if (
                        soar_tenant.integration
                        and soar_tenant.integration.id not in data["integration_ids"]
                    ):
                        raise serializers.ValidationError(
                            {
                                "soar_tenant_ids": f"Cortex Soar tenant {soar_tenant.id} is linked to integration {soar_tenant.integration.id}, which is not included in integration_ids"
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
            soar_tenant_ids = validated_data.pop("soar_tenant_ids", [])

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

            # Handle soar_tenants
            soar_tenants = []
            if soar_tenant_ids:
                logger.debug("Processing soar_tenant_ids: %s", soar_tenant_ids)
                for soar_id in soar_tenant_ids:
                    soar_tenant = DuCortexSOARTenants.objects.get(
                        id=soar_id
                    )  # Already validated
                    soar_tenants.append(soar_tenant)
                tenant.soar_tenants.set(soar_tenants)

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


# class TenantUpdateSerializer(serializers.ModelSerializer):
#     qradar_tenants = QradarTenantInputSerializer(many=True, required=False)
#     integration_ids = serializers.ListField(
#         child=serializers.IntegerField(), required=False
#     )
#     itsm_tenant_ids = serializers.ListField(
#         child=serializers.IntegerField(), required=False
#     )
#     soar_tenant_ids = serializers.ListField(
#         child=serializers.IntegerField(), required=False
#     )
#     role_permissions = serializers.ListField(
#         child=serializers.IntegerField(), required=False
#     )

#     class Meta:
#         model = Tenant
#         fields = [
#             "qradar_tenants",
#             "integration_ids",
#             "itsm_tenant_ids",
#             "soar_tenant_ids",
#             "role_permissions",
#         ]

#     def validate(self, data):
#         integration_ids = data.get("integration_ids", [])
#         if integration_ids:
#             integrations = Integration.objects.filter(id__in=integration_ids)
#             if integrations.count() != len(integration_ids):
#                 invalid = set(integration_ids) - set(
#                     integrations.values_list("id", flat=True)
#                 )
#                 raise serializers.ValidationError(
#                     {"integration_ids": f"Invalid ids: {invalid}"}
#                 )

#         tenant_id = self.instance.id

#         if "itsm_tenant_ids" in data:
#             itsm_qs = DuITSMTenants.objects.filter(
#                 id__in=data["itsm_tenant_ids"]
#             ).select_related("integration")
#             if itsm_qs.count() != len(data["itsm_tenant_ids"]):
#                 raise serializers.ValidationError(
#                     {"itsm_tenant_ids": "One or more invalid IDs"}
#                 )
#             for item in itsm_qs:
#                 if item.integration and item.integration.id not in integration_ids:
#                     raise serializers.ValidationError(
#                         {
#                             "itsm_tenant_ids": f"ITSM tenant {item.id} linked to integration {item.integration.id} not in integration_ids"
#                         }
#                     )
#                 if item.tenant_set.exclude(id=tenant_id).exists():
#                     raise serializers.ValidationError(
#                         {
#                             "itsm_tenant_ids": f"ITSM tenant {item.id} is already assigned to another tenant"
#                         }
#                     )

#         if "soar_tenant_ids" in data:
#             soar_qs = DuCortexSOARTenants.objects.filter(
#                 id__in=data["soar_tenant_ids"]
#             ).select_related("integration")
#             if soar_qs.count() != len(data["soar_tenant_ids"]):
#                 raise serializers.ValidationError(
#                     {"soar_tenant_ids": "One or more invalid IDs"}
#                 )
#             for item in soar_qs:
#                 if item.integration and item.integration.id not in integration_ids:
#                     raise serializers.ValidationError(
#                         {
#                             "soar_tenant_ids": f"SOAR tenant {item.id} linked to integration {item.integration.id} not in integration_ids"
#                         }
#                     )
#                 if item.tenant_set.exclude(id=tenant_id).exists():
#                     raise serializers.ValidationError(
#                         {
#                             "soar_tenant_ids": f"SOAR tenant {item.id} is already assigned to another tenant"
#                         }
#                     )

#         if "qradar_tenants" in data:
#             all_ec_ids = []
#             for qt in data["qradar_tenants"]:
#                 qtid = qt["qradar_tenant_id"]
#                 if (
#                     DuIbmQradarTenants.objects.filter(id=qtid, tenant__isnull=False)
#                     .exclude(tenant__id=tenant_id)
#                     .exists()
#                 ):
#                     raise serializers.ValidationError(
#                         {"qradar_tenants": f"QRadar tenant {qtid} already assigned"}
#                     )
#                 ecs = qt.get("event_collector_ids", [])
#                 ec_qs = IBMQradarEventCollector.objects.filter(id__in=ecs)
#                 if ec_qs.count() != len(ecs):
#                     raise serializers.ValidationError(
#                         {
#                             "qradar_tenants": f"Invalid event_collector_ids: {set(ecs) - set(ec_qs.values_list('id', flat=True))}"
#                         }
#                     )
#                 all_ec_ids.extend(ecs)
#             if len(all_ec_ids) != len(set(all_ec_ids)):
#                 raise serializers.ValidationError(
#                     {"qradar_tenants": "Duplicate event collector ids across tenants"}
#                 )

#         return data

#     def update(self, instance, validated_data):
#         with transaction.atomic():
#             integration_ids = validated_data.pop("integration_ids", None)
#             if integration_ids is not None:
#                 instance.integrations.set(
#                     Integration.objects.filter(id__in=integration_ids)
#                 )

#             if "itsm_tenant_ids" in validated_data:
#                 instance.itsm_tenants.set(
#                     DuITSMTenants.objects.filter(
#                         id__in=validated_data["itsm_tenant_ids"]
#                     )
#                 )

#             if "soar_tenant_ids" in validated_data:
#                 instance.soar_tenants.set(
#                     DuCortexSOARTenants.objects.filter(
#                         id__in=validated_data["soar_tenant_ids"]
#                     )
#                 )

#             if "qradar_tenants" in validated_data:
#                 # Clear existing mappings
#                 TenantQradarMapping.objects.filter(tenant=instance).delete()
#                 all_ecs = []
#                 for qt in validated_data["qradar_tenants"]:
#                     qradar = DuIbmQradarTenants.objects.get(id=qt["qradar_tenant_id"])
#                     mapping = TenantQradarMapping.objects.create(
#                         tenant=instance, qradar_tenant=qradar
#                     )
#                     ecs = IBMQradarEventCollector.objects.filter(
#                         id__in=qt["event_collector_ids"]
#                     )
#                     mapping.event_collectors.set(ecs)
#                     all_ecs.extend(ecs)
#                 instance.event_collectors.set(all_ecs)

#             if "role_permissions" in validated_data:
#                 role = instance.roles.filter(
#                     role_type=TenantRole.TenantRoleChoices.TENANT_ADMIN
#                 ).first()
#                 if role:
#                     role.permissions.all().delete()
#                     for perm in validated_data["role_permissions"]:
#                         TenantRolePermissions.objects.create(role=role, permission=perm)

#             instance.save()
#             return instance


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


class DuCortexSOARTenantsSerializer(serializers.ModelSerializer):
    class Meta:
        model = DuCortexSOARTenants
        fields = ["id", "name"]


class IBMQradarAssestsSerializer(serializers.ModelSerializer):
    log_source_type_name = serializers.CharField(
        source="log_source_type.name", read_only=True
    )

    class Meta:
        model = IBMQradarAssests
        fields = "__all__"
        extra_fields = ["log_source_type_name"]


class DuITSMTicketsSerializer(serializers.ModelSerializer):
    class Meta:
        model = DuITSMFinalTickets
        fields = "__all__"


class DUCortexSOARIncidentSerializer(serializers.ModelSerializer):
    class Meta:
        model = DUCortexSOARIncidentFinalModel
        fields = "__all__"


class IBMQradarEPSSerializer(serializers.ModelSerializer):
    class Meta:
        model = IBMQradarEPS
        fields = ["log_source", "domain", "eps"]
