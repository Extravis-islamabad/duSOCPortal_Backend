# tenant/serializers.py
from django.db import transaction
from django.db.models import Count
from loguru import logger
from rest_framework import serializers

from authentication.models import User
from common.modules.cyware import Cyware
from integration.models import (
    Integration,
    IntegrationTypes,
    ItsmSubTypes,
    SiemSubTypes,
    SoarSubTypes,
    ThreatIntelligenceSubTypes,
)

from .models import (
    Alert,
    DUCortexSOARIncidentFinalModel,
    DuCortexSOARTenants,
    DuIbmQradarTenants,
    DuITSMFinalTickets,
    DuITSMTenants,
    IBMQradarAssests,
    IBMQradarEPS,
    IBMQradarEventCollector,
    Tenant,
    TenantQradarMapping,
    TenantRole,
    TenantRolePermissions,
    ThreatIntelligenceTenant,
)


class TenantUpdateSerializer(serializers.ModelSerializer):
    permissions = serializers.ListField(
        child=serializers.IntegerField(min_value=1, max_value=5),
        required=False,
    )
    integration_ids = serializers.ListField(
        child=serializers.IntegerField(), required=False
    )
    itsm_tenant_ids = serializers.ListField(
        child=serializers.IntegerField(), required=False
    )
    soar_tenant_ids = serializers.ListField(
        child=serializers.IntegerField(), required=False
    )
    is_defualt_threat_intel = serializers.BooleanField(required=False)
    qradar_tenants = serializers.ListField(
        child=serializers.DictField(), required=False
    )
    threat_intelligence = serializers.IntegerField(required=False)
    access_key = serializers.CharField(required=False, allow_blank=True)
    secret_key = serializers.CharField(required=False, allow_blank=True)
    base_url = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = Tenant
        fields = [
            "permissions",
            "integration_ids",
            "itsm_tenant_ids",
            "soar_tenant_ids",
            "is_defualt_threat_intel",
            "qradar_tenants",
            "threat_intelligence",
            "access_key",
            "secret_key",
            "base_url",
        ]

    def validate(self, data):
        if "integration_ids" in data:
            if not data["integration_ids"]:
                raise serializers.ValidationError(
                    {"integration_ids": "At least one integration ID is required"}
                )
            existing = Integration.objects.filter(
                id__in=data["integration_ids"]
            ).values_list("id", flat=True)
            missing = set(data["integration_ids"]) - set(existing)
            if missing:
                raise serializers.ValidationError(
                    {"integration_ids": f"Invalid integration IDs: {missing}"}
                )

        if "itsm_tenant_ids" in data:
            existing = DuITSMTenants.objects.filter(
                id__in=data["itsm_tenant_ids"]
            ).values_list("id", flat=True)
            missing = set(data["itsm_tenant_ids"]) - set(existing)
            if missing:
                raise serializers.ValidationError(
                    {"itsm_tenant_ids": f"Invalid ITSM tenant IDs: {missing}"}
                )

        if "soar_tenant_ids" in data:
            existing = DuCortexSOARTenants.objects.filter(
                id__in=data["soar_tenant_ids"]
            ).values_list("id", flat=True)
            missing = set(data["soar_tenant_ids"]) - set(existing)
            if missing:
                raise serializers.ValidationError(
                    {"soar_tenant_ids": f"Invalid SOAR tenant IDs: {missing}"}
                )

        if "qradar_tenants" in data:
            for qt in data["qradar_tenants"]:
                qt_id = qt.get("qradar_tenant_id")
                if not DuIbmQradarTenants.objects.filter(id=qt_id).exists():
                    raise serializers.ValidationError(
                        {"qradar_tenants": f"Invalid QRadar tenant ID: {qt_id}"}
                    )
                for ec_id in qt.get("event_collector_ids", []):
                    if not IBMQradarEventCollector.objects.filter(id=ec_id).exists():
                        raise serializers.ValidationError(
                            {"qradar_tenants": f"Invalid Event Collector ID: {ec_id}"}
                        )

                    # existing_mappings = TenantQradarMapping.objects.filter(
                    #     event_collectors__id=ec_id
                    # ).exclude(tenant=self.instance)
                    # if existing_mappings.exists():
                    #     raise serializers.ValidationError(
                    #         {
                    #             "qradar_tenants": f"Event Collector ID {ec_id} is already assigned to another tenant."
                    #         }
                    #     )

        if data.get("is_defualt_threat_intel") is False:
            required_fields = [
                "threat_intelligence",
                "access_key",
                "secret_key",
                "base_url",
            ]
            for field in required_fields:
                if not data.get(field):
                    raise serializers.ValidationError(
                        {
                            field: f"{field} is required when default threat intel is disabled."
                        }
                    )

        return data

    def update(self, instance, validated_data):
        permissions = validated_data.pop("permissions", None)
        integration_ids = validated_data.pop("integration_ids", None)
        itsm_ids = validated_data.pop("itsm_tenant_ids", None)
        soar_ids = validated_data.pop("soar_tenant_ids", None)
        qradar_data = validated_data.pop("qradar_tenants", None)
        is_defualt_threat_intel = validated_data.get("is_defualt_threat_intel", None)

        threat_intelligence = validated_data.get("threat_intelligence")
        access_key = validated_data.get("access_key")
        secret_key = validated_data.get("secret_key")
        base_url = validated_data.get("base_url")

        company_name = instance.tenant.company_name
        related_tenants = Tenant.objects.filter(tenant__company_name=company_name)

        for tenant in related_tenants:
            if integration_ids is not None:
                tenant.integrations.set(
                    Integration.objects.filter(id__in=integration_ids)
                )
            if itsm_ids is not None:
                tenant.itsm_tenants.set(DuITSMTenants.objects.filter(id__in=itsm_ids))
            if soar_ids is not None:
                tenant.soar_tenants.set(
                    DuCortexSOARTenants.objects.filter(id__in=soar_ids)
                )
            if is_defualt_threat_intel is not None:
                tenant.is_defualt_threat_intel = is_defualt_threat_intel

            if permissions is not None:
                role, _ = TenantRole.objects.get_or_create(
                    tenant=tenant,
                    defaults={
                        "name": f"{tenant.tenant.username} Admin",
                        "role_type": TenantRole.TenantRoleChoices.TENANT_ADMIN,
                    },
                )
                TenantRolePermissions.objects.filter(role=role).delete()
                for perm in permissions:
                    TenantRolePermissions.objects.create(role=role, permission=perm)

            if qradar_data is not None:
                for qt in qradar_data:
                    qradar_tenant = DuIbmQradarTenants.objects.get(
                        id=qt["qradar_tenant_id"]
                    )
                    mapping, _ = TenantQradarMapping.objects.get_or_create(
                        tenant=tenant, qradar_tenant=qradar_tenant
                    )
                    mapping.event_collectors.set(
                        IBMQradarEventCollector.objects.filter(
                            id__in=qt.get("event_collector_ids", [])
                        )
                    )

            if is_defualt_threat_intel is False and threat_intelligence and base_url:
                ti_obj, _ = ThreatIntelligenceTenant.objects.get_or_create(
                    base_url=base_url,
                    defaults={
                        "threat_intelligence": threat_intelligence,
                        "access_key": access_key,
                        "secret_key": secret_key,
                    },
                )
                ti_obj.tenants.add(tenant)

            tenant.save()

        return instance


class TenantRolePermissionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = TenantRolePermissions
        fields = ["permission", "permission_text"]


class AllTenantDetailSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="tenant.username", read_only=True)
    email = serializers.EmailField(source="tenant.email", read_only=True)
    permissions = serializers.SerializerMethodField()
    tenant_admin = serializers.SerializerMethodField()
    total_incidents = serializers.SerializerMethodField()
    active_incidents = serializers.SerializerMethodField()
    tickets_count = serializers.SerializerMethodField()
    sla = serializers.SerializerMethodField()
    asset_count = serializers.SerializerMethodField()
    created_by_id = serializers.IntegerField(source="created_by.id", read_only=True)
    role = serializers.SerializerMethodField()

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
            "created_by_id",
            "role",
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

    def get_role(self, obj):
        try:
            role = obj.roles.get()
            return role.get_role_type_display()
        except Exception:
            return None


# class TenantDetailSerializer(serializers.ModelSerializer):
#     username = serializers.CharField(source="tenant.username", read_only=True)
#     email = serializers.EmailField(source="tenant.email", read_only=True)
#     company_name = serializers.CharField(source="tenant.company_name", read_only=True)
#     permissions = serializers.SerializerMethodField()
#     tenant_admin = serializers.SerializerMethodField()
#     created_by_id = serializers.IntegerField(source="created_by.id", read_only=True)
#     role = serializers.SerializerMethodField()
#     total_incidents = serializers.SerializerMethodField()
#     active_incidents = serializers.SerializerMethodField()
#     tickets_count = serializers.SerializerMethodField()
#     sla = serializers.SerializerMethodField()
#     asset_count = serializers.SerializerMethodField()
#     tenant_data = serializers.SerializerMethodField()
#     qradar_tenants = serializers.SerializerMethodField()

#     class Meta:
#         model = Tenant
#         fields = [
#             "id",
#             "username",
#             "email",
#             "company_name",
#             "phone_number",
#             "country",
#             "created_at",
#             "updated_at",
#             "permissions",
#             "asset_count",
#             "total_incidents",
#             "active_incidents",
#             "tickets_count",
#             "sla",
#             "tenant_admin",
#             "created_by_id",
#             "role",
#             "tenant_data",
#             "qradar_tenants",
#             "integrations",
#             "itsm_tenants",
#             "soar_tenants",
#             "is_defualt_threat_intel",
#         ]

#     def get_permissions(self, obj):
#         try:
#             role = obj.roles.get()
#             return [
#                 {"id": perm.permission, "name": perm.permission_text}
#                 for perm in role.role_permissions.all()
#             ]
#         except Exception as e:
#             logger.error(e)
#             return []

#     def get_role(self, obj):
#         try:
#             role = obj.roles.get()
#             return role.get_role_type_display()
#         except Exception:
#             return None

#     def get_tenant_admin(self, obj):
#         if obj.tenant:
#             return obj.created_by.username if obj.created_by else None
#         return None

#     def get_asset_count(self, obj):
#         try:
#             collector_ids = TenantQradarMapping.objects.filter(tenant=obj).values_list(
#                 "event_collectors__id", flat=True
#             )
#             asset_count = IBMQradarAssests.objects.filter(
#                 event_collector__id__in=collector_ids
#             ).aggregate(totalAssets=Count("id"))
#             return asset_count["totalAssets"] or 0
#         except Exception:
#             return 0

#     def get_active_incidents(self, obj):
#         return self.get_total_incidents(obj)

#     def get_sla(self, obj):
#         try:
#             return obj.sla.name
#         except Exception:
#             return 0

#     def get_total_incidents(self, obj):
#         try:
#             soar_tenants = obj.soar_tenants.all()
#             return DUCortexSOARIncidentFinalModel.objects.filter(
#                 cortex_soar_tenant__in=soar_tenants
#             ).count()
#         except Exception:
#             return 0

#     def get_tickets_count(self, obj):
#         try:
#             itsm_tenants = obj.itsm_tenants.all()
#             return DuITSMFinalTickets.objects.filter(
#                 itsm_tenant__in=itsm_tenants
#             ).count()
#         except Exception:
#             return 0

#     def get_tenant_data(self, obj):
#         return {
#             "tenant_id": obj.tenant.id if obj.tenant else None,
#             "tenant_username": obj.tenant.username if obj.tenant else None,
#             "tenant_email": obj.tenant.email if obj.tenant else None,
#             "tenant_company_name": obj.tenant.company_name if obj.tenant else None,
#         }

#     def get_qradar_tenants(self, obj):
#         try:
#             mappings = TenantQradarMapping.objects.filter(tenant=obj)
#             return [
#                 {
#                     "qradar_tenant_id": mapping.qradar_tenant.id,
#                     "event_collector_ids": list(
#                         mapping.event_collectors.values_list("id", flat=True)
#                     ),
#                 }
#                 for mapping in mappings
#             ]
#         except Exception:
#             return []


class TenantDetailSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="tenant.username", read_only=True)
    email = serializers.EmailField(source="tenant.email", read_only=True)
    company_name = serializers.CharField(source="tenant.company_name", read_only=True)
    permissions = serializers.SerializerMethodField()
    tenant_admin = serializers.SerializerMethodField()
    created_by_id = serializers.IntegerField(source="created_by.id", read_only=True)
    role = serializers.SerializerMethodField()
    total_incidents = serializers.SerializerMethodField()
    active_incidents = serializers.SerializerMethodField()
    tickets_count = serializers.SerializerMethodField()
    sla = serializers.SerializerMethodField()
    asset_count = serializers.SerializerMethodField()
    tenant_data = serializers.SerializerMethodField()
    qradar_tenants = serializers.SerializerMethodField()
    integrations = serializers.SerializerMethodField()
    ldap_group = serializers.CharField(read_only=True)

    class Meta:
        model = Tenant
        fields = [
            "id",
            "username",
            "email",
            "company_name",
            "phone_number",
            "country",
            "created_at",
            "updated_at",
            "permissions",
            "asset_count",
            "total_incidents",
            "active_incidents",
            "tickets_count",
            "sla",
            "tenant_admin",
            "created_by_id",
            "role",
            "tenant_data",
            "qradar_tenants",
            "integrations",
            "itsm_tenants",
            "soar_tenants",
            "is_defualt_threat_intel",
            "ldap_group",
        ]

    def get_permissions(self, obj):
        try:
            role = obj.roles.get()
            return [
                {"id": perm.permission, "name": perm.permission_text}
                for perm in role.role_permissions.all()
            ]
        except Exception:
            return []

    def get_role(self, obj):
        try:
            role = obj.roles.get()
            return role.get_role_type_display()
        except Exception:
            return None

    def get_tenant_admin(self, obj):
        if obj.tenant:
            return obj.created_by.username if obj.created_by else None
        return None

    def get_asset_count(self, obj):
        try:
            collector_ids = TenantQradarMapping.objects.filter(tenant=obj).values_list(
                "event_collectors__id", flat=True
            )
            asset_count = IBMQradarAssests.objects.filter(
                event_collector__id__in=collector_ids
            ).count()
            return asset_count
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

    def get_tenant_data(self, obj):
        return {
            "tenant_id": obj.tenant.id if obj.tenant else None,
            "tenant_username": obj.tenant.username if obj.tenant else None,
            "tenant_email": obj.tenant.email if obj.tenant else None,
            "tenant_company_name": obj.tenant.company_name if obj.tenant else None,
        }

    def get_qradar_tenants(self, obj):
        try:
            mappings = TenantQradarMapping.objects.filter(tenant=obj)
            return [
                {
                    "qradar_tenant_id": mapping.qradar_tenant.id,
                    "event_collector_ids": list(
                        mapping.event_collectors.values_list("id", flat=True)
                    ),
                }
                for mapping in mappings
            ]
        except Exception:
            return []

    def get_integrations(self, obj):
        integrations = obj.integrations.all()
        result = []
        for integration in integrations:
            data = {
                "id": integration.id,
                "instance_name": integration.instance_name,
                "integration_type": integration.integration_type,
                "integration_type_text": IntegrationTypes(
                    integration.integration_type
                ).label,
                "siem_subtype": integration.siem_subtype,
                "siem_subtype_text": SiemSubTypes(integration.siem_subtype).label
                if integration.siem_subtype
                else None,
                "soar_subtype": integration.soar_subtype,
                "soar_subtype_text": SoarSubTypes(integration.soar_subtype).label
                if integration.soar_subtype
                else None,
                "itsm_subtype": integration.itsm_subtype,
                "itsm_subtype_text": ItsmSubTypes(integration.itsm_subtype).label
                if integration.itsm_subtype
                else None,
                "threat_intelligence_subtype": integration.threat_intelligence_subtype,
                "threat_intelligence_subtype_text": ThreatIntelligenceSubTypes(
                    integration.threat_intelligence_subtype
                ).label
                if integration.threat_intelligence_subtype
                else None,
            }
            result.append(data)
        return result


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
    ldap_users = serializers.ListField(
        child=serializers.DictField(),
        required=True,
        write_only=True,
    )
    ldap_group = serializers.CharField(required=True, write_only=True)
    qradar_tenants = QradarTenantInputSerializer(
        many=True, required=False, write_only=True
    )
    integration_ids = serializers.ListField(
        child=serializers.IntegerField(), required=False, write_only=True
    )
    itsm_tenant_ids = serializers.ListField(
        child=serializers.IntegerField(), required=False, write_only=True
    )
    soar_tenant_ids = serializers.ListField(
        child=serializers.IntegerField(), required=False, write_only=True
    )
    role_permissions = serializers.ListField(
        child=serializers.IntegerField(), required=False, write_only=True
    )
    is_defualt_threat_intel = serializers.BooleanField(required=False, write_only=True)
    threat_intelligence = serializers.IntegerField(required=False, write_only=True)
    access_key = serializers.CharField(
        required=False, allow_blank=True, write_only=True
    )
    secret_key = serializers.CharField(
        required=False, allow_blank=True, write_only=True
    )
    base_url = serializers.CharField(required=False, allow_blank=True, write_only=True)

    class Meta:
        model = Tenant
        fields = [
            "ldap_users",
            "ldap_group",
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
            "is_defualt_threat_intel",
            "threat_intelligence",
            "access_key",
            "secret_key",
            "base_url",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def validate(self, data):
        ldap_users = data.get("ldap_users")
        if not ldap_users:
            raise serializers.ValidationError(
                {"ldap_users": "At least one LDAP user is required"}
            )
        ldap_group = data.get("ldap_group")
        if not ldap_group:
            raise serializers.ValidationError(
                {"ldap_group": "At least one LDAP group is required"}
            )

        existing_usernames = User.objects.filter(
            username__in=[u["username"] for u in ldap_users]
        ).values_list("username", flat=True)
        if existing_usernames:
            raise serializers.ValidationError(
                {
                    "ldap_users": f"User(s) with username(s) {list(existing_usernames)} already exist."
                }
            )
        usernames = [u["username"] for u in ldap_users]
        if len(usernames) != len(set(usernames)):
            raise serializers.ValidationError(
                {"ldap_users": "Duplicate usernames detected"}
            )

        if not any(user.get("is_admin") for user in ldap_users):
            raise serializers.ValidationError(
                {"ldap_users": "At least one user must be marked as is_admin=True"}
            )

        integration_ids = data.get("integration_ids", [])
        if integration_ids:
            integrations = Integration.objects.filter(id__in=integration_ids)
            if len(integrations) != len(integration_ids):
                existing_ids = set(integrations.values_list("id", flat=True))
                missing = set(integration_ids) - existing_ids
                raise serializers.ValidationError(
                    {"integration_ids": f"Invalid integration IDs: {missing}"}
                )

        if "qradar_tenants" in data:
            for qt in data["qradar_tenants"]:
                if not DuIbmQradarTenants.objects.filter(
                    id=qt["qradar_tenant_id"]
                ).exists():
                    raise serializers.ValidationError(
                        {
                            "qradar_tenants": f"Invalid QRadar tenant ID: {qt['qradar_tenant_id']}"
                        }
                    )
                for ec_id in qt.get("event_collector_ids", []):
                    if not IBMQradarEventCollector.objects.filter(id=ec_id).exists():
                        raise serializers.ValidationError(
                            {"qradar_tenants": f"Invalid Event Collector ID: {ec_id}"}
                        )

        if "itsm_tenant_ids" in data:
            itsm_ids = data["itsm_tenant_ids"]
            found = DuITSMTenants.objects.filter(id__in=itsm_ids).values_list(
                "id", flat=True
            )
            if len(found) != len(itsm_ids):
                missing = set(itsm_ids) - set(found)
                raise serializers.ValidationError(
                    {"itsm_tenant_ids": f"Invalid ITSM tenant IDs: {missing}"}
                )

        if "soar_tenant_ids" in data:
            soar_ids = data["soar_tenant_ids"]
            found = DuCortexSOARTenants.objects.filter(id__in=soar_ids).values_list(
                "id", flat=True
            )
            if len(found) != len(soar_ids):
                missing = set(soar_ids) - set(found)
                raise serializers.ValidationError(
                    {"soar_tenant_ids": f"Invalid SOAR tenant IDs: {missing}"}
                )

        return data

    def create(self, validated_data):
        ldap_group = validated_data.pop("ldap_group")
        ldap_users = validated_data.pop("ldap_users")
        role_permissions = validated_data.pop("role_permissions", [])
        integration_ids = validated_data.pop("integration_ids", [])
        qradar_tenants_data = validated_data.pop("qradar_tenants", [])
        itsm_tenant_ids = validated_data.pop("itsm_tenant_ids", [])
        soar_tenant_ids = validated_data.pop("soar_tenant_ids", [])
        is_defualt_threat_intel = validated_data.pop("is_defualt_threat_intel", True)
        threat_intelligence = validated_data.pop("threat_intelligence", None)
        access_key = validated_data.pop("access_key", None)
        secret_key = validated_data.pop("secret_key", None)
        base_url = validated_data.pop("base_url", None)

        created_by = self.context["request"].user

        created_tenants = []

        with transaction.atomic():
            for index, user_data in enumerate(ldap_users):
                email = user_data.get("email")
                email = None if email == "N/A" else email
                user, created = User.objects.get_or_create(
                    username=user_data["username"],
                    defaults={
                        "email": email,
                        "name": user_data.get("name"),
                        "is_tenant": True,
                        "is_active": True,
                    },
                )

                tenant = Tenant.objects.create(
                    tenant=user,
                    created_by=created_by,
                    ldap_group=ldap_group,
                    is_defualt_threat_intel=is_defualt_threat_intel,
                    **validated_data,
                )

                role_type = (
                    TenantRole.TenantRoleChoices.TENANT_ADMIN
                    if user_data.get("is_admin")
                    else TenantRole.TenantRoleChoices.TENANT_USER
                )
                role = TenantRole.objects.create(
                    tenant=tenant,
                    name="Tenant Admin" if role_type == 1 else "Tenant User",
                    role_type=role_type,
                )

                for permission in role_permissions:
                    TenantRolePermissions.objects.create(
                        role=role, permission=permission
                    )

                if integration_ids:
                    tenant.integrations.set(
                        Integration.objects.filter(id__in=integration_ids)
                    )

                if itsm_tenant_ids:
                    tenant.itsm_tenants.set(
                        DuITSMTenants.objects.filter(id__in=itsm_tenant_ids)
                    )

                if soar_tenant_ids:
                    tenant.soar_tenants.set(
                        DuCortexSOARTenants.objects.filter(id__in=soar_tenant_ids)
                    )

                for qt in qradar_tenants_data:
                    qradar_tenant = DuIbmQradarTenants.objects.get(
                        id=qt["qradar_tenant_id"]
                    )
                    mapping = TenantQradarMapping.objects.create(
                        tenant=tenant, qradar_tenant=qradar_tenant
                    )
                    mapping.event_collectors.set(
                        IBMQradarEventCollector.objects.filter(
                            id__in=qt.get("event_collector_ids", [])
                        )
                    )

                created_tenants.append(tenant)
            if not is_defualt_threat_intel and threat_intelligence and base_url:
                try:
                    with Cyware(
                        base_url=base_url,
                        secret_key=secret_key,
                        access_key=access_key,
                    ) as cyware:
                        response = cyware.get_alert_list()
                        if response.status_code != 200:
                            raise serializers.ValidationError(
                                "Cyware integration is not accessible."
                            )
                except Exception:
                    raise serializers.ValidationError(
                        "Failed to validate Cyware integration."
                    )

                ti_obj, _ = ThreatIntelligenceTenant.objects.get_or_create(
                    base_url=base_url,
                    defaults={
                        "threat_intelligence": threat_intelligence,
                        "access_key": access_key,
                        "secret_key": secret_key,
                    },
                )
                ti_obj.tenants.set(created_tenants)

        return created_tenants


# class TenantCreateSerializer(serializers.ModelSerializer):
#     email = serializers.EmailField(write_only=True, required=False, allow_null=True)
#     username = serializers.CharField(write_only=True, required=False, allow_null=True)
#     name = serializers.CharField(write_only=True, required=False, allow_null=True)
#     password = serializers.CharField(
#         write_only=True,
#         style={"input_type": "password"},
#         required=False,
#         allow_null=True,
#     )
#     qradar_tenants = QradarTenantInputSerializer(
#         many=True, required=False, write_only=True
#     )
#     integration_ids = serializers.ListField(
#         child=serializers.IntegerField(), required=False, write_only=True
#     )
#     itsm_tenant_ids = serializers.ListField(
#         child=serializers.IntegerField(), required=False, write_only=True
#     )
#     role_permissions = serializers.ListField(
#         child=serializers.IntegerField(), required=False, write_only=True
#     )
#     soar_tenant_ids = serializers.ListField(
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
#             "qradar_tenants",
#             "integration_ids",
#             "itsm_tenant_ids",
#             "soar_tenant_ids",
#             "role_permissions",
#             "id",
#             "created_at",
#             "updated_at",
#         ]
#         read_only_fields = ["id", "created_at", "updated_at"]

#     def validate(self, data):
#         logger.debug("Starting validation with data: %s", data)
#         is_admin = self.context["request"].user.is_admin
#         if not is_admin and not (data.get("email") or data.get("username")):
#             raise serializers.ValidationError(
#                 {
#                     "error": "At least one of email or username must be provided for tenants"
#                 }
#             )

#         if "integration_ids" in data and len(data["integration_ids"]) == 0:
#             raise serializers.ValidationError(
#                 {"integration_ids": "At least one integration is required"}
#             )
#         if (
#             "qradar_tenants" in data
#             and len(data["qradar_tenants"]) == 0
#             and "itsm_tenant_ids"
#             and len(data["itsm_tenant_ids"]) == 0
#             and "soar_tenant_ids" in data
#             and len(data["soar_tenant_ids"]) == 0
#         ):
#             raise serializers.ValidationError(
#                 {
#                     "error": "At least one qradar tenant or itsm tenant or soar tenant is required"
#                 }
#             )
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

#         # Validate qradar_tenants
#         if "qradar_tenants" in data:
#             qradar_tenant_ids = [
#                 qt["qradar_tenant_id"] for qt in data["qradar_tenants"]
#             ]
#             if len(qradar_tenant_ids) != len(set(qradar_tenant_ids)):
#                 raise serializers.ValidationError(
#                     {"qradar_tenants": "Duplicate qradar_tenant_ids are not allowed"}
#                 )

#             # Validate qradar_tenant_ids and event_collector_ids
#             all_event_collector_ids = []
#             for qt in data["qradar_tenants"]:
#                 # Check qradar_tenant_id
#                 qradar_tenant_id = qt["qradar_tenant_id"]
#                 if TenantQradarMapping.objects.filter(
#                     qradar_tenant_id=qradar_tenant_id
#                 ).exists():
#                     raise serializers.ValidationError(
#                         {
#                             "qradar_tenants": f"QRadar tenant ID {qradar_tenant_id} is already assigned to another tenant"
#                         }
#                     )
#                 if not DuIbmQradarTenants.objects.filter(
#                     id=qt["qradar_tenant_id"]
#                 ).exists():
#                     raise serializers.ValidationError(
#                         {
#                             "qradar_tenants": f"Invalid qradar_tenant_id: {qt['qradar_tenant_id']}"
#                         }
#                     )
#                 # Check event_collector_ids
#                 event_collector_ids = qt["event_collector_ids"]
#                 if event_collector_ids:
#                     valid_event_collectors = IBMQradarEventCollector.objects.filter(
#                         id__in=event_collector_ids
#                     )
#                     if len(valid_event_collectors) != len(event_collector_ids):
#                         invalid_ids = set(event_collector_ids) - set(
#                             ec.id for ec in valid_event_collectors
#                         )
#                         raise serializers.ValidationError(
#                             {
#                                 "qradar_tenants": f"Invalid event_collector_ids: {invalid_ids} for qradar_tenant_id: {qt['qradar_tenant_id']}"
#                             }
#                         )
#                     all_event_collector_ids.extend(event_collector_ids)

#             # Ensure no duplicate event_collector_ids across qradar_tenants
#             if len(all_event_collector_ids) != len(set(all_event_collector_ids)):
#                 raise serializers.ValidationError(
#                     {
#                         "qradar_tenants": "Duplicate event_collector_ids across qradar_tenants are not allowed"
#                     }
#                 )

#         # Validate integration_ids
#         if "integration_ids" in data:
#             integrations = Integration.objects.filter(id__in=data["integration_ids"])
#             if len(integrations) != len(data["integration_ids"]):
#                 invalid_ids = set(data["integration_ids"]) - set(
#                     intg.id for intg in integrations
#                 )
#                 raise serializers.ValidationError(
#                     {"integration_ids": f"Invalid integration_ids: {invalid_ids}"}
#                 )

#         if "itsm_tenant_ids" in data:
#             itsm_tenants = DuITSMTenants.objects.filter(
#                 id__in=data["itsm_tenant_ids"]
#             ).select_related("integration")
#             if len(itsm_tenants) != len(data["itsm_tenant_ids"]):
#                 invalid_ids = set(data["itsm_tenant_ids"]) - set(
#                     itsm.id for itsm in itsm_tenants
#                 )
#                 raise serializers.ValidationError(
#                     {"itsm_tenant_ids": f"Invalid itsm_tenant_ids: {invalid_ids}"}
#                 )
#             if "integration_ids" in data:
#                 for itsm_tenant in itsm_tenants:
#                     if (
#                         itsm_tenant.integration
#                         and itsm_tenant.integration.id not in data["integration_ids"]
#                     ):
#                         raise serializers.ValidationError(
#                             {
#                                 "itsm_tenant_ids": f"ITSM tenant {itsm_tenant.id} is linked to integration {itsm_tenant.integration.id}, which is not included in integration_ids"
#                             }
#                         )

#         if "soar_tenant_ids" in data:
#             soar_tenants = DuCortexSOARTenants.objects.filter(
#                 id__in=data["soar_tenant_ids"]
#             ).select_related("integration")
#             if len(soar_tenants) != len(data["soar_tenant_ids"]):
#                 invalid_ids = set(data["soar_tenant_ids"]) - set(
#                     itsm.id for itsm in soar_tenants
#                 )
#                 raise serializers.ValidationError(
#                     {"soar_tenant_ids": f"Invalid soar_tenant_ids: {invalid_ids}"}
#                 )
#             if "integration_ids" in data:
#                 for soar_tenant in soar_tenants:
#                     if (
#                         soar_tenant.integration
#                         and soar_tenant.integration.id not in data["integration_ids"]
#                     ):
#                         raise serializers.ValidationError(
#                             {
#                                 "soar_tenant_ids": f"Cortex Soar tenant {soar_tenant.id} is linked to integration {soar_tenant.integration.id}, which is not included in integration_ids"
#                             }
#                         )

#         logger.debug("Validation passed")
#         return data

#     def create(self, validated_data):
#         logger.debug("Starting tenant creation with validated_data: %s", validated_data)

#         with transaction.atomic():
#             # Extract user data
#             user_data = {
#                 "email": validated_data.pop("email", None),
#                 "username": validated_data.pop("username", None),
#                 "name": validated_data.pop("name", None),
#                 "password": validated_data.pop("password", None),
#             }
#             role_permissions = validated_data.pop("role_permissions", [])
#             integration_ids = validated_data.pop("integration_ids", [])
#             qradar_tenants_data = validated_data.pop("qradar_tenants", [])
#             itsm_tenant_ids = validated_data.pop("itsm_tenant_ids", [])
#             soar_tenant_ids = validated_data.pop("soar_tenant_ids", [])

#             # Create User
#             logger.debug("Checking for existing user")
#             if user_data.get("email", None):
#                 if User.objects.filter(email=user_data["email"]).exists():
#                     raise serializers.ValidationError(
#                         {"email": "User with this email already exists"}
#                     )
#             if User.objects.filter(username=user_data["username"]).exists():
#                 raise serializers.ValidationError(
#                     {"username": "User with this username already exists"}
#                 )

#             logger.debug("Creating user")
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
#             logger.debug("Created by: %s", created_by)

#             # Create Tenant
#             logger.debug("Creating tenant")
#             tenant = Tenant.objects.create(
#                 tenant=user,
#                 created_by=created_by,
#                 **validated_data,
#             )

#             # Handle qradar_tenants and event_collectors
#             all_event_collectors = []
#             for qt_data in qradar_tenants_data:
#                 logger.debug("Processing qradar_tenant: %s", qt_data)
#                 qradar_tenant = DuIbmQradarTenants.objects.get(
#                     id=qt_data["qradar_tenant_id"]
#                 )  # Already validated
#                 event_collectors = []
#                 for ec_id in qt_data["event_collector_ids"]:
#                     ec = IBMQradarEventCollector.objects.get(
#                         id=ec_id
#                     )  # Already validated
#                     event_collectors.append(ec)
#                     if ec not in all_event_collectors:
#                         all_event_collectors.append(ec)

#                 # Create mapping
#                 mapping = TenantQradarMapping.objects.create(
#                     tenant=tenant, qradar_tenant=qradar_tenant
#                 )
#                 mapping.event_collectors.set(event_collectors)

#             # Handle itsm_tenants
#             itsm_tenants = []
#             if itsm_tenant_ids:
#                 logger.debug("Processing itsm_tenant_ids: %s", itsm_tenant_ids)
#                 for itsm_id in itsm_tenant_ids:
#                     itsm_tenant = DuITSMTenants.objects.get(
#                         id=itsm_id
#                     )  # Already validated
#                     itsm_tenants.append(itsm_tenant)
#                 tenant.itsm_tenants.set(itsm_tenants)

#             # Handle soar_tenants
#             soar_tenants = []
#             if soar_tenant_ids:
#                 logger.debug("Processing soar_tenant_ids: %s", soar_tenant_ids)
#                 for soar_id in soar_tenant_ids:
#                     soar_tenant = DuCortexSOARTenants.objects.get(
#                         id=soar_id
#                     )  # Already validated
#                     soar_tenants.append(soar_tenant)
#                 tenant.soar_tenants.set(soar_tenants)

#             # Handle integrations
#             integrations = []
#             if integration_ids:
#                 logger.debug("Processing integration_ids: %s", integration_ids)
#                 for int_id in integration_ids:
#                     integration = Integration.objects.get(
#                         id=int_id
#                     )  # Already validated
#                     integrations.append(integration)
#                 tenant.integrations.set(integrations)

#             # Associate all event collectors with tenant
#             if all_event_collectors:
#                 logger.debug("Associating event collectors: %s", all_event_collectors)
#                 tenant.event_collectors.set(all_event_collectors)

#             # Create TenantRole
#             logger.debug("Creating tenant role")
#             role = TenantRole.objects.create(
#                 tenant=tenant,
#                 name="Tenant Admin",
#                 role_type=TenantRole.TenantRoleChoices.TENANT_ADMIN,
#             )

#             # Create TenantRolePermissions
#             for permission in role_permissions:
#                 logger.debug("Creating role permission: %s", permission)
#                 TenantRolePermissions.objects.create(role=role, permission=permission)

#             logger.debug("Tenant creation completed successfully")
#             return tenant


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
    log_source = serializers.CharField(source="log_source.name", read_only=True)

    class Meta:
        model = IBMQradarEPS
        fields = ["log_source", "domain", "eps"]


class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = [
            "id",
            "db_id",
            "title",
            "status",
            "published_time",
            "created_at",
            "updated_at",
        ]
