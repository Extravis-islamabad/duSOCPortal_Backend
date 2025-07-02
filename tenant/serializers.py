# tenant/serializers.py
from django.db import transaction
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

from .models import (  # SoarTenantSlaMetric,
    Alert,
    Company,
    CustomerEPS,
    CywareAlertDetails,
    CywareCategories,
    CywareCustomField,
    CywareGroup,
    CywareTag,
    CywareTenantAlertDetails,
    CywareTenantCategories,
    CywareTenantCustomField,
    CywareTenantGroup,
    CywareTenantTag,
    DefaultSoarSlaMetric,
    DUCortexSOARIncidentFinalModel,
    DuCortexSOARTenants,
    DuIbmQradarTenants,
    DuITSMFinalTickets,
    DuITSMTenants,
    IBMQradarAssests,
    IBMQradarEPS,
    IBMQradarEventCollector,
    SlaLevelChoices,
    SoarTenantSlaMetric,
    Tenant,
    TenantQradarMapping,
    TenantRole,
    TenantRolePermissions,
    ThreatIntelligenceTenant,
    VolumeTypeChoices,
)


class CompanyTenantUpdateSerializer(serializers.Serializer):
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

    def validate(self, data):
        if "integration_ids" in data:
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
                    existing_mappings = TenantQradarMapping.objects.filter(
                        event_collectors__id=ec_id
                    ).exclude(company=self.context["company"])
                    if existing_mappings.exists():
                        raise serializers.ValidationError(
                            {
                                "qradar_tenants": f"Event Collector ID {ec_id} is already assigned to another tenant."
                            }
                        )

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

    def update(self, company, validated_data):
        tenants = company.tenants.all()

        permissions = validated_data.pop("permissions", None)
        integration_ids = validated_data.pop("integration_ids", None)
        itsm_ids = validated_data.pop("itsm_tenant_ids", None)
        soar_ids = validated_data.pop("soar_tenant_ids", None)
        qradar_data = validated_data.pop("qradar_tenants", None)
        is_defualt_threat_intel = validated_data.get("is_defualt_threat_intel", None)

        if "integration_ids" in validated_data:
            company.integrations.set(Integration.objects.filter(id__in=integration_ids))
        if "itsm_tenant_ids" in validated_data:
            company.itsm_tenants.set(DuITSMTenants.objects.filter(id__in=itsm_ids))
        if "soar_tenant_ids" in validated_data:
            company.soar_tenants.set(
                DuCortexSOARTenants.objects.filter(id__in=soar_ids)
            )
        if "is_defualt_threat_intel" in validated_data:
            company.is_defualt_threat_intel = validated_data["is_defualt_threat_intel"]

        company.save()

        for tenant in tenants:
            if permissions is not None:
                existing_role = TenantRole.objects.filter(tenant=tenant).first()
                role, _ = TenantRole.objects.get_or_create(
                    tenant=tenant,
                    defaults={
                        "name": existing_role.name
                        if existing_role
                        else f"{tenant.tenant.username} Role",
                        "role_type": existing_role.role_type
                        if existing_role
                        else TenantRole.TenantRoleChoices.TENANT_USER,
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
                        company=company, qradar_tenant=qradar_tenant
                    )
                    mapping.event_collectors.set(
                        IBMQradarEventCollector.objects.filter(
                            id__in=qt.get("event_collector_ids", [])
                        )
                    )
                    if "contracted_volume_type" in qt:
                        mapping.contracted_volume_type = qt["contracted_volume_type"]
                    if "contracted_volume" in qt:
                        mapping.contracted_volume = qt["contracted_volume"]
                    mapping.save()

            if is_defualt_threat_intel is False and validated_data.get("base_url"):
                with Cyware(
                    base_url=validated_data["base_url"],
                    secret_key=validated_data["secret_key"],
                    access_key=validated_data["access_key"],
                ) as cyware:
                    response = cyware.get_alert_list(timeout=5)
                    if response.status_code != 200:
                        raise serializers.ValidationError(
                            "Cyware integration is not accessible."
                        )
                ti_obj, _ = ThreatIntelligenceTenant.objects.get_or_create(
                    base_url=validated_data["base_url"],
                    defaults={
                        "threat_intelligence": validated_data["threat_intelligence"],
                        "access_key": validated_data["access_key"],
                        "secret_key": validated_data["secret_key"],
                    },
                )
                ti_obj.tenants.add(tenant)

            tenant.save()

        return company


class TenantRolePermissionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = TenantRolePermissions
        fields = ["permission", "permission_text"]


class AllTenantDetailSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="tenant.username", read_only=True)
    email = serializers.EmailField(source="tenant.email", read_only=True)
    permissions = serializers.SerializerMethodField()
    tenant_admin = serializers.SerializerMethodField()
    # total_incidents = serializers.SerializerMethodField()
    # active_incidents = serializers.SerializerMethodField()
    # tickets_count = serializers.SerializerMethodField()
    # sla = serializers.SerializerMethodField()
    # asset_count = serializers.SerializerMethodField()
    created_by_id = serializers.IntegerField(source="created_by.id", read_only=True)
    role = serializers.SerializerMethodField()

    # ✅ Fields from Company
    company_name = serializers.SerializerMethodField()
    phone_number = serializers.SerializerMethodField()
    industry = serializers.SerializerMethodField()
    country = serializers.SerializerMethodField()
    profile_picture = serializers.SerializerMethodField()

    class Meta:
        model = Tenant
        fields = [
            "id",
            "username",
            "email",
            "company_name",
            "phone_number",
            "industry",
            "country",
            "profile_picture",
            "created_at",
            "updated_at",
            "permissions",
            # "asset_count",
            # "total_incidents",
            # "active_incidents",
            # "tickets_count",
            # "sla",
            "tenant_admin",
            "created_by_id",
            "role",
        ]

    def get_company_name(self, obj):
        return obj.company.company_name if obj.company else None

    def get_phone_number(self, obj):
        return obj.company.phone_number if obj.company else None

    def get_industry(self, obj):
        return obj.company.industry if obj.company else None

    def get_country(self, obj):
        return obj.company.country if obj.company else None

    def get_profile_picture(self, obj):
        if obj.company and obj.company.profile_picture:
            request = self.context.get("request")
            return request.build_absolute_uri(obj.company.profile_picture.url)
        return None

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

    # def get_asset_count(self, obj):
    #     try:
    #         collector_ids = TenantQradarMapping.objects.filter(tenant=obj).values_list(
    #             "event_collectors__id", flat=True
    #         )
    #         asset_count = IBMQradarAssests.objects.filter(
    #             event_collector__id__in=collector_ids
    #         ).aggregate(totalAssets=Count("id"))
    #         return asset_count["totalAssets"] or 0
    #     except Exception:
    #         return 0

    # def get_active_incidents(self, obj):
    #     return self.get_total_incidents(obj)

    # def get_sla(self, obj):
    #     try:
    #         return obj.sla.name
    #     except Exception:
    #         return None

    # def get_total_incidents(self, obj):
    #     try:
    #         soar_tenants = obj.soar_tenants.all()
    #         return DUCortexSOARIncidentFinalModel.objects.filter(
    #             cortex_soar_tenant__in=soar_tenants
    #         ).count()
    #     except Exception:
    #         return 0

    # def get_tickets_count(self, obj):
    #     try:
    #         itsm_tenants = obj.itsm_tenants.all()
    #         return DuITSMFinalTickets.objects.filter(
    #             itsm_tenant__in=itsm_tenants
    #         ).count()
    #     except Exception:
    #         return 0

    def get_role(self, obj):
        try:
            role = obj.roles.get()
            return role.get_role_type_display()
        except Exception:
            return None


class TenantDetailSerializer(serializers.ModelSerializer):
    company_name = serializers.CharField(source="company.company_name", read_only=True)
    phone_number = serializers.CharField(source="company.phone_number", read_only=True)
    country = serializers.CharField(source="company.country", read_only=True)
    industry = serializers.CharField(source="company.industry", read_only=True)
    logo_url = serializers.SerializerMethodField()
    created_by_id = serializers.IntegerField(source="created_by.id", read_only=True)
    ldap_group = serializers.CharField(read_only=True)
    is_defualt_threat_intel = serializers.BooleanField(
        source="company.is_defualt_threat_intel", read_only=True
    )
    is_default_sla = serializers.BooleanField(
        source="company.is_default_sla", read_only=True
    )

    asset_count = serializers.SerializerMethodField()
    total_incidents = serializers.SerializerMethodField()
    active_incidents = serializers.SerializerMethodField()
    tickets_count = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()
    role_info = serializers.SerializerMethodField()
    permissions = serializers.SerializerMethodField()
    qradar_tenants = serializers.SerializerMethodField()
    integrations = serializers.SerializerMethodField()
    itsm_tenants = serializers.SerializerMethodField()
    soar_tenants = serializers.SerializerMethodField()
    related_tenants = serializers.SerializerMethodField()

    class Meta:
        model = Tenant
        fields = [
            "id",
            "company_name",
            "phone_number",
            "industry",
            "country",
            "created_at",
            "updated_at",
            "ldap_group",
            "created_by_id",
            "logo_url",
            "is_defualt_threat_intel",
            "is_default_sla",
            "asset_count",
            "total_incidents",
            "active_incidents",
            "tickets_count",
            "role",
            "role_info",
            "permissions",
            "qradar_tenants",
            "integrations",
            "itsm_tenants",
            "soar_tenants",
            "related_tenants",
        ]

    def get_logo_url(self, obj):
        company = obj.company
        if (
            company
            and company.profile_picture
            and hasattr(company.profile_picture, "url")
        ):
            request = self.context.get("request")
            if request:
                return request.build_absolute_uri(company.profile_picture.url)
        return None

    def get_asset_count(self, obj):
        try:
            collector_ids = TenantQradarMapping.objects.filter(tenant=obj).values_list(
                "event_collectors__id", flat=True
            )
            return IBMQradarAssests.objects.filter(
                event_collector__id__in=collector_ids
            ).count()
        except Exception:
            return 0

    def get_total_incidents(self, obj):
        try:
            return DUCortexSOARIncidentFinalModel.objects.filter(
                cortex_soar_tenant__in=obj.soar_tenants.all()
            ).count()
        except Exception:
            return 0

    def get_active_incidents(self, obj):
        return self.get_total_incidents(obj)

    def get_tickets_count(self, obj):
        try:
            return DuITSMFinalTickets.objects.filter(
                itsm_tenant__in=obj.itsm_tenants.all()
            ).count()
        except Exception:
            return 0

    def get_role(self, obj):
        try:
            return obj.roles.get().get_role_type_display()
        except Exception:
            return None

    def get_role_info(self, obj):
        try:
            role = obj.roles.get()
            return {
                "name": role.name,
                "type": role.get_role_type_display(),
                "permissions": [
                    {"id": perm.permission, "name": perm.permission_text}
                    for perm in role.role_permissions.all()
                ],
            }
        except Exception:
            return None

    def get_permissions(self, obj):
        try:
            role = obj.roles.get()
            return [
                {"id": perm.permission, "name": perm.permission_text}
                for perm in role.role_permissions.all()
            ]
        except Exception:
            return []

    def get_qradar_tenants(self, obj):
        try:
            mappings = TenantQradarMapping.objects.filter(company=obj.company)
            return [
                {
                    "qradar_tenant_id": mapping.qradar_tenant.id,
                    "qradar_tenant_name": mapping.qradar_tenant.name,
                    "event_collectors": [
                        {"id": c.id, "name": c.name}
                        for c in mapping.event_collectors.all()
                    ],
                    "contracted_volume_type": {
                        "id": mapping.contracted_volume_type,
                        "text": mapping.get_contracted_volume_type_display(),
                    }
                    if mapping.contracted_volume_type is not None
                    else None,
                    "contracted_volume": mapping.contracted_volume,
                }
                for mapping in mappings
            ]
        except Exception:
            return []

    def get_integrations(self, obj):
        result = []
        for integration in obj.company.integrations.all():
            result.append(
                {
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
            )
        return result

    def get_itsm_tenants(self, obj):
        try:
            return [
                {"id": t.id, "name": t.name} for t in obj.company.itsm_tenants.all()
            ]
        except Exception:
            return []

    def get_soar_tenants(self, obj):
        try:
            tenants = obj.company.soar_tenants.all()
            result = []
            for tenant in tenants:
                if obj.company.is_default_sla:
                    metrics = DefaultSoarSlaMetric.objects.all()
                else:
                    metrics = SoarTenantSlaMetric.objects.filter(
                        tenant=obj, soar_tenant=tenant
                    )
                sla_overrides = [
                    {
                        "sla_level": m.sla_level,
                        "sla_level_text": SlaLevelChoices(m.sla_level).label,
                        "tta_minutes": m.tta_minutes,
                        "ttn_minutes": m.ttn_minutes,
                        "ttdn_minutes": m.ttdn_minutes,
                    }
                    for m in metrics
                ]
                result.append(
                    {
                        "soar_tenant_id": tenant.id,
                        "soar_tenant_name": tenant.name,
                        "sla_overrides": sla_overrides,
                    }
                )
            return result
        except Exception:
            return []

    def get_related_tenants(self, obj):
        if not obj.company:
            return []
        related = Tenant.objects.filter(company=obj.company)
        result = []
        for tenant in related:
            try:
                role = tenant.roles.get()
                role_data = {"name": role.name, "type": role.get_role_type_display()}
            except Exception:
                role_data = None

            result.append(
                {
                    "id": tenant.id,
                    "phone_number": tenant.company.phone_number
                    if tenant.company
                    else None,
                    "country": tenant.company.country if tenant.company else None,
                    "created_at": tenant.created_at,
                    "is_active": tenant.tenant.is_active if tenant.tenant else None,
                    "role": role_data,
                    "industry": tenant.company.industry if tenant.company else None,
                    "username": tenant.tenant.username if tenant.tenant else None,
                    "email": tenant.tenant.email if tenant.tenant else None,
                }
            )
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
    contracted_volume_type = serializers.ChoiceField(
        choices=VolumeTypeChoices.choices, required=True
    )
    contracted_volume = serializers.FloatField(required=True)


class SlaOverrideSerializer(serializers.Serializer):
    sla_level = serializers.ChoiceField(choices=SlaLevelChoices.choices)
    tta_minutes = serializers.IntegerField()
    ttn_minutes = serializers.IntegerField()
    ttdn_minutes = serializers.IntegerField()


class SoarTenantInputSerializer(serializers.Serializer):
    soar_tenant_id = serializers.IntegerField()
    sla_overrides = SlaOverrideSerializer(many=True, required=False)


class TenantCreateSerializer(serializers.ModelSerializer):
    ldap_users = serializers.ListField(
        child=serializers.DictField(),
        required=True,
        write_only=True,
    )
    qradar_tenants = QradarTenantInputSerializer(
        many=True, required=False, write_only=True
    )
    integration_ids = serializers.ListField(
        child=serializers.IntegerField(), required=False, write_only=True
    )
    itsm_tenant_ids = serializers.ListField(
        child=serializers.IntegerField(), required=False, write_only=True
    )
    soar_tenants = SoarTenantInputSerializer(many=True, required=False, write_only=True)
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
    company_name = serializers.CharField(write_only=True)
    is_default_sla = serializers.BooleanField(write_only=True)

    phone_number = serializers.CharField(write_only=True)
    industry = serializers.CharField(write_only=True)
    country = serializers.CharField(write_only=True)

    class Meta:
        model = Tenant
        fields = [
            "ldap_users",
            "ldap_group",
            "phone_number",
            "industry",
            "country",
            "qradar_tenants",
            "integration_ids",
            "itsm_tenant_ids",
            "soar_tenants",
            "role_permissions",
            "id",
            "company_name",
            "is_default_sla",
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
        company_name = data.get("company_name")
        if Company.objects.filter(company_name__iexact=company_name).exists():
            raise serializers.ValidationError(
                {"company_name": "Company name already exists"}
            )

        ldap_users = data.get("ldap_users")
        if not ldap_users:
            raise serializers.ValidationError(
                {"ldap_users": "At least one LDAP user is required"}
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

        if not all(user.get("ldap_group") for user in ldap_users):
            raise serializers.ValidationError(
                {"ldap_users": "Each user must have a non-empty ldap_group."}
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
                if "contracted_volume_type" not in qt or "contracted_volume" not in qt:
                    raise serializers.ValidationError(
                        {
                            "qradar_tenants": "Both 'contracted_volume_type' and 'contracted_volume' are required for each QRadar tenant"
                        }
                    )
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
        if "soar_tenants" in data and not data.get("is_default_sla", True):
            required_levels = {level for level, _ in SlaLevelChoices.choices}
            for soar in data["soar_tenants"]:
                provided_levels = {
                    sla["sla_level"] for sla in soar.get("sla_overrides", [])
                }
                if provided_levels != required_levels:
                    raise serializers.ValidationError(
                        {
                            "soar_tenants": "Custom SLA must cover all SLA levels (P1 to P4)"
                        }
                    )

        if "soar_tenants" in data:
            soar_ids = [s["soar_tenant_id"] for s in data["soar_tenants"]]
            already_assigned = DuCortexSOARTenants.objects.filter(
                id__in=soar_ids, company__isnull=False
            ).values_list("id", flat=True)
            if already_assigned:
                raise serializers.ValidationError(
                    {
                        "soar_tenants": f"SOAR tenants already assigned: {list(already_assigned)}"
                    }
                )

        if "qradar_tenants" in data:
            qradar_ids = [q["qradar_tenant_id"] for q in data["qradar_tenants"]]

            # Check if DuIbmQradarTenants already assigned to a company
            already_assigned = DuIbmQradarTenants.objects.filter(
                id__in=qradar_ids, company__isnull=False
            ).values_list("id", flat=True)
            if already_assigned:
                raise serializers.ValidationError(
                    {
                        "qradar_tenants": f"QRadar tenants already assigned: {list(already_assigned)}"
                    }
                )

            # Check if TenantQradarMapping already has qradar_tenant assigned to another company
            mapping_assigned = TenantQradarMapping.objects.filter(
                qradar_tenant_id__in=qradar_ids
            ).values_list("qradar_tenant_id", flat=True)
            if mapping_assigned:
                raise serializers.ValidationError(
                    {
                        "qradar_tenants": f"QRadar tenant IDs already mapped: {list(mapping_assigned)}"
                    }
                )

        if "itsm_tenant_ids" in data:
            itsm_ids = data["itsm_tenant_ids"]
            already_assigned = DuITSMTenants.objects.filter(
                id__in=itsm_ids, company__isnull=False
            ).values_list("id", flat=True)
            if already_assigned:
                raise serializers.ValidationError(
                    {
                        "itsm_tenant_ids": f"ITSM tenants already assigned: {list(already_assigned)}"
                    }
                )

        return data

    def create(self, validated_data):
        industry = validated_data.pop("industry")
        ldap_users = validated_data.pop("ldap_users")
        role_permissions = validated_data.pop("role_permissions", [])
        integration_ids = validated_data.pop("integration_ids", [])
        qradar_tenants_data = validated_data.pop("qradar_tenants", [])
        itsm_tenant_ids = validated_data.pop("itsm_tenant_ids", [])
        soar_tenant_data = validated_data.pop("soar_tenants", [])
        is_defualt_threat_intel = validated_data.pop("is_defualt_threat_intel", True)
        threat_intelligence = validated_data.pop("threat_intelligence", None)
        access_key = validated_data.pop("access_key", None)
        secret_key = validated_data.pop("secret_key", None)
        base_url = validated_data.pop("base_url", None)
        is_default_sla = validated_data.pop("is_default_sla", False)
        company_name = validated_data.pop("company_name", None)
        phone_number = validated_data.pop("phone_number", None)
        country = validated_data.pop("country", None)
        created_by = self.context["request"].user

        with transaction.atomic():
            company = Company.objects.create(
                company_name=company_name,
                created_by=created_by,
                phone_number=phone_number,
                industry=industry,
                is_default_sla=is_default_sla,
                is_defualt_threat_intel=is_defualt_threat_intel,
                country=country,
            )

            for user_data in ldap_users:
                email = user_data.get("email")
                email = None if email == "N/A" else email
                user, _ = User.objects.get_or_create(
                    username=user_data["username"],
                    defaults={
                        "email": email,
                        "name": user_data.get("name"),
                        "is_tenant": True,
                        "is_active": True,
                    },
                )
                ldap_group = user_data["ldap_group"]
                tenant = Tenant.objects.create(
                    tenant=user,
                    company=company,
                    created_by=created_by,
                    ldap_group=ldap_group,
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
                company.integrations.set(
                    Integration.objects.filter(id__in=integration_ids)
                )

            if itsm_tenant_ids:
                company.itsm_tenants.set(
                    DuITSMTenants.objects.filter(id__in=itsm_tenant_ids)
                )

            for soar in soar_tenant_data:
                soar_tenant = DuCortexSOARTenants.objects.get(id=soar["soar_tenant_id"])
                company.soar_tenants.set(
                    DuCortexSOARTenants.objects.filter(id=soar["soar_tenant_id"])
                )
                if not is_default_sla:
                    for override in soar.get("sla_overrides", []):
                        SoarTenantSlaMetric.objects.create(
                            company=tenant.company,
                            soar_tenant=soar_tenant,
                            sla_level=override["sla_level"],
                            tta_minutes=override["tta_minutes"],
                            ttn_minutes=override["ttn_minutes"],
                            ttdn_minutes=override["ttdn_minutes"],
                        )
            for qt in qradar_tenants_data:
                qradar_tenant = DuIbmQradarTenants.objects.get(
                    id=qt["qradar_tenant_id"]
                )
                mapping = TenantQradarMapping.objects.create(
                    company=company,
                    qradar_tenant=qradar_tenant,
                    contracted_volume_type=qt["contracted_volume_type"],
                    contracted_volume=qt["contracted_volume"],
                )
                mapping.event_collectors.set(
                    IBMQradarEventCollector.objects.filter(
                        id__in=qt.get("event_collector_ids", [])
                    )
                )

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

                if not is_defualt_threat_intel and threat_intelligence and base_url:
                    ThreatIntelligenceTenant.objects.get_or_create(
                        base_url=base_url,
                        defaults={
                            "threat_intelligence": threat_intelligence,
                            "access_key": access_key,
                            "secret_key": secret_key,
                            "company": company,
                        },
                    )

        return company


class CustomerEPSSerializer(serializers.ModelSerializer):
    qradar_tenant_name = serializers.CharField(
        source="qradar_tenant.name", read_only=True
    )
    qradar_tenant_id = serializers.IntegerField(
        source="qradar_tenant.id", read_only=True
    )
    qradar_tenant_db_id = serializers.IntegerField(
        source="qradar_tenant.db_id", read_only=True
    )

    class Meta:
        model = CustomerEPS
        fields = [
            "eps",
            "qradar_tenant_id",
            "qradar_tenant_db_id",
            "qradar_tenant_name",
        ]


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


class RecentIncidentsSerializer(serializers.ModelSerializer):
    class Meta:
        model = DUCortexSOARIncidentFinalModel
        fields = "__all__"


class CywareCustomFieldSerializer(serializers.ModelSerializer):
    class Meta:
        model = CywareCustomField

        fields = "__all__"


class CywareGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = CywareGroup

        fields = "__all__"


class CywareTagSerializer(serializers.ModelSerializer):
    class Meta:
        model = CywareTag

        fields = "__all__"


class CywareCategoriesSerializer(serializers.ModelSerializer):
    class Meta:
        model = CywareCategories

        fields = "__all__"


class CywareAlertDetailsSerializer(serializers.ModelSerializer):
    card_groups = CywareGroupSerializer(many=True, read_only=True)

    recipient_groups = CywareGroupSerializer(many=True, read_only=True)

    card_tag = CywareTagSerializer(many=True, read_only=True)

    card_category = CywareCategoriesSerializer(read_only=True)

    class Meta:
        model = CywareAlertDetails

        fields = "__all__"


class CywareCategoriesSerializer(serializers.ModelSerializer):
    threat_indicator_fields = CywareCustomFieldSerializer(many=True, read_only=True)

    additional_fields = CywareCustomFieldSerializer(many=True, read_only=True)

    required_fields = CywareCustomFieldSerializer(many=True, read_only=True)

    class Meta:
        model = CywareCategories

        fields = "__all__"


class CywareTenantCustomFieldSerializer(serializers.ModelSerializer):
    class Meta:
        model = CywareTenantCustomField

        fields = "__all__"


class CywareTenantGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = CywareTenantGroup

        fields = "__all__"


class CywareTenantTagSerializer(serializers.ModelSerializer):
    class Meta:
        model = CywareTenantTag

        fields = "__all__"


class CywareTenantCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = CywareTenantCategories

        fields = "__all__"


class CywareTenantAlertDetailsSerializer(serializers.ModelSerializer):
    card_groups = CywareTenantGroupSerializer(many=True, read_only=True)

    recipient_groups = CywareTenantGroupSerializer(many=True, read_only=True)

    card_tag = CywareTenantTagSerializer(many=True, read_only=True)

    card_category = CywareTenantCategorySerializer(read_only=True)

    class Meta:
        model = CywareTenantAlertDetails

        fields = "__all__"


class CywareTenantCategorySerializer(serializers.ModelSerializer):
    threat_indicator_fields = CywareTenantCustomFieldSerializer(
        many=True, read_only=True
    )

    additional_fields = CywareTenantCustomFieldSerializer(many=True, read_only=True)

    required_fields = CywareTenantCustomFieldSerializer(many=True, read_only=True)

    class Meta:
        model = CywareTenantCategories

        fields = "__all__"


# Serializers
class IncidentSerializer(serializers.ModelSerializer):
    class Meta:
        model = DUCortexSOARIncidentFinalModel
        fields = [
            "id",
            "db_id",
            "created",
            "severity",
            "status",
            "incident_tta",
            "incident_ttn",
            "incident_ttdn",
        ]


class SlaMetricSerializer(serializers.ModelSerializer):
    class Meta:
        model = DefaultSoarSlaMetric
        fields = ["sla_level", "tta_minutes", "ttn_minutes", "ttdn_minutes"]
