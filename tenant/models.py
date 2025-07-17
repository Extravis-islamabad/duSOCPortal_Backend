from datetime import datetime

from django.db import models
from django.utils import timezone
from loguru import logger

from authentication.models import User
from integration.models import Integration, ThreatIntelligenceSubTypes


class DuIbmQradarTenants(models.Model):
    id = models.AutoField(primary_key=True)
    db_id = models.IntegerField(unique=True)
    name = models.CharField(max_length=255, blank=True, default=None)
    integration = models.ForeignKey(
        Integration,
        on_delete=models.CASCADE,
        related_name="du_ibm_qradar_tenants",
        null=True,
        blank=True,
    )

    class Meta:
        db_table = "du_ibm_qradar_tenants"

    def __str__(self):
        return self.name


class IBMQradarEventCollector(models.Model):
    id = models.AutoField(primary_key=True)
    db_id = models.IntegerField(unique=True)
    name = models.CharField(max_length=255, blank=True, default=None)
    host_id = models.IntegerField()
    component_name = models.CharField(max_length=255, blank=True, default=None)
    integration = models.ForeignKey(
        Integration,
        on_delete=models.CASCADE,
        related_name="du_ibm_qradar_event_collectors",
        null=True,
        blank=True,
    )

    class Meta:
        db_table = "du_ibm_qradar_event_collector"

    def __str__(self):
        return self.name


class IBMQradarLogSourceTypes(models.Model):
    id = models.AutoField(primary_key=True)
    db_id = models.IntegerField(unique=True)
    name = models.CharField(max_length=255)
    version = models.CharField(max_length=50, blank=True, default=None, null=True)
    integration = models.ForeignKey(
        Integration,
        on_delete=models.CASCADE,
        related_name="du_ibm_qradar_log_source_types",
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "ibm_qradar_log_source_types"
        ordering = ["-created_at"]


class IBMQradarAssests(models.Model):
    id = models.AutoField(primary_key=True)
    db_id = models.IntegerField(unique=True)
    name = models.CharField(max_length=255, blank=True, default=None)
    description = models.CharField(max_length=255, blank=True, default=None)
    integration = models.ForeignKey(
        Integration,
        on_delete=models.CASCADE,
        related_name="du_ibm_qradar_assets",
        null=True,
        blank=True,
    )
    target_event_collector_id = models.IntegerField(null=True, blank=True)
    sending_ip = models.CharField(max_length=255, blank=True, default=None, null=True)
    enabled = models.BooleanField(default=False)
    status = models.CharField(max_length=255, blank=True, default=None, null=True)
    event_collector = models.ForeignKey(
        IBMQradarEventCollector,
        on_delete=models.CASCADE,
        null=False,
        blank=False,
        default=None,
    )
    log_source_type = models.ForeignKey(
        IBMQradarLogSourceTypes,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        default=None,
    )

    average_eps = models.IntegerField(default=0)
    creation_date = models.CharField(max_length=255, blank=True, default=None)
    modified_date = models.CharField(max_length=255, blank=True, default=None)
    last_event_time = models.CharField(max_length=255, blank=True, default=None)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    creation_date_converted = models.DateField(null=True, blank=True)
    modified_date_converted = models.DateField(null=True, blank=True)
    last_event_date_converted = models.DateField(null=True, blank=True)

    class Meta:
        db_table = "du_ibm_qradar_assets"

    def save(self, *args, **kwargs):
        # Helper to convert timestamp string to date
        def parse_timestamp(ts_str):
            try:
                if not ts_str or str(ts_str).strip() in ("0", "", "null"):
                    return None
                ts = int(ts_str)
                return datetime.utcfromtimestamp(ts / 1000).date()
            except (ValueError, TypeError):
                return None

        self.creation_date_converted = parse_timestamp(self.creation_date)
        self.modified_date_converted = parse_timestamp(self.modified_date)
        self.last_event_date_converted = parse_timestamp(self.last_event_time)

        super().save(*args, **kwargs)


class IBMQradarEPS(models.Model):
    log_source = models.ForeignKey(
        IBMQradarAssests,
        on_delete=models.CASCADE,
        related_name="du_ibm_qradar_eps",
    )
    domain = models.ForeignKey(
        DuIbmQradarTenants,
        on_delete=models.CASCADE,
        related_name="du_ibm_qradar_eps",
    )
    integration = models.ForeignKey(
        Integration,
        on_delete=models.CASCADE,
        related_name="du_ibm_qradar_eps",
        null=True,
        blank=True,
    )
    eps = models.FloatField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "du_ibm_qradar_eps"


class CustomerEPS(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    customer = models.CharField(max_length=255, unique=True)
    eps = models.FloatField()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "customer_eps"

    def __str__(self):
        return f"{self.customer} - EPS: {self.eps}"


class IBMQradarOffense(models.Model):
    id = models.AutoField(primary_key=True)
    db_id = models.IntegerField(unique=True)  # Maps to 'id' in JSON
    qradar_tenant_domain = models.ForeignKey(
        DuIbmQradarTenants,
        on_delete=models.CASCADE,
        related_name="du_ibm_qradar_offenses",
    )
    assests = models.ManyToManyField(
        IBMQradarAssests,
        related_name="du_ibm_qradar_offenses",
    )
    integration = models.ForeignKey(
        Integration,
        on_delete=models.CASCADE,
        related_name="du_ibm_qradar_offenses",
        null=True,
        blank=True,
    )
    description = models.TextField(blank=True, null=True)
    event_count = models.IntegerField(default=0)
    flow_count = models.IntegerField(default=0)
    assigned_to = models.CharField(max_length=255, blank=True, null=True)
    security_category_count = models.IntegerField(default=0)
    follow_up = models.BooleanField(default=False)
    source_address_ids = models.JSONField(default=list)  # Store as JSON array
    source_count = models.IntegerField(default=0)
    inactive = models.BooleanField(default=False)
    protected = models.BooleanField(default=False)
    closing_user = models.CharField(max_length=255, blank=True, null=True)
    destination_networks = models.JSONField(default=list)  # Store as JSON array
    source_network = models.CharField(max_length=255, blank=True, null=True)
    category_count = models.IntegerField(default=0)
    close_time = models.BigIntegerField(null=True, blank=True)
    remote_destination_count = models.IntegerField(default=0)
    start_time = models.BigIntegerField()
    magnitude = models.IntegerField(default=0)
    last_updated_time = models.BigIntegerField()
    last_persisted_time = models.BigIntegerField()
    first_persisted_time = models.BigIntegerField()
    credibility = models.IntegerField(default=0)
    severity = models.IntegerField(default=0)
    policy_category_count = models.IntegerField(default=0)
    closing_reason_id = models.IntegerField(null=True, blank=True)
    device_count = models.IntegerField(default=0)
    offense_type = models.IntegerField(default=0)
    relevance = models.IntegerField(default=0)
    offense_source = models.CharField(max_length=255, blank=True, null=True)
    local_destination_address_ids = models.JSONField(
        default=list
    )  # Store as JSON array
    local_destination_count = models.IntegerField(default=0)
    status = models.CharField(max_length=50, blank=True, null=True)
    categories = models.JSONField(default=list)  # Store as JSON array
    rules = models.JSONField(default=list)  # Store as JSON array

    start_date = models.DateField(null=True, blank=True)
    last_updated_date = models.DateField(null=True, blank=True)
    last_persisted_date = models.DateField(null=True, blank=True)
    first_persisted_date = models.DateField(null=True, blank=True)

    class Meta:
        db_table = "du_ibm_qradar_offenses"

    def save(self, *args, **kwargs):
        def parse_ts(ts):
            try:
                if ts in (None, 0, "0"):
                    return None
                return datetime.utcfromtimestamp(int(ts) / 1000).date()
            except Exception as e:
                logger.warning(f"Failed to convert timestamp {ts}: {e}")
                return None

        self.start_date = parse_ts(self.start_time)
        self.last_updated_date = parse_ts(self.last_updated_time)
        self.last_persisted_date = parse_ts(self.last_persisted_time)
        self.first_persisted_date = parse_ts(self.first_persisted_time)

        super().save(*args, **kwargs)

    def __str__(self):
        return f"Offense {self.db_id} - {self.description}"


class DuITSMTenants(models.Model):
    id = models.AutoField(primary_key=True)
    db_id = models.IntegerField(unique=True, default=None)
    name = models.CharField(max_length=255, blank=True, default=None)
    integration = models.ForeignKey(
        Integration,
        on_delete=models.CASCADE,
        related_name="du_itsm_tenants",
        null=True,
        blank=True,
    )

    class Meta:
        db_table = "du_itsm_tenants"

    def __str__(self):
        return self.name


class DuITSMFinalTickets(models.Model):
    id = models.AutoField(primary_key=True)
    db_id = models.IntegerField(unique=True)
    short_description = models.TextField()
    subject = models.TextField()
    is_overdue = models.BooleanField(default=False)
    creation_date = models.CharField(max_length=255, blank=True, default=None)
    created_by_name = models.CharField(max_length=255, blank=True, default=None)
    account_name = models.CharField(max_length=255, blank=True, default=None)
    soar_id = models.IntegerField(null=True, blank=True)
    itsm_tenant = models.ForeignKey(
        DuITSMTenants,
        on_delete=models.CASCADE,
        related_name="du_itsm_final_tickets",
        null=True,
        blank=True,
    )
    integration = models.ForeignKey(
        Integration,
        on_delete=models.CASCADE,
        related_name="du_itsm_final_tickets",
        null=True,
        blank=True,
    )
    status = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "du_itsm_final_tickets"

    def __str__(self):
        return f"{self.short_description}"


class DuCortexSOARTenants(models.Model):
    id = models.AutoField(primary_key=True)
    db_id = models.IntegerField(unique=True)
    name = models.CharField(max_length=255, blank=True, default=None)
    integration = models.ForeignKey(
        Integration,
        on_delete=models.CASCADE,
        related_name="du_cortex_soar_tenants",
        null=True,
        blank=True,
    )

    class Meta:
        db_table = "du_cortex_soar_tenants"

    def __str__(self):
        return self.name


class DUCortexSOARIncidentFinalModel(models.Model):
    id = models.AutoField(primary_key=True)
    db_id = models.IntegerField(null=True, blank=True)
    created = models.DateTimeField()
    modified = models.DateTimeField()
    account = models.CharField(max_length=255, null=True, blank=True)
    name = models.CharField(max_length=255, null=True, blank=True)
    status = models.CharField(max_length=50, null=True, blank=True)
    reason = models.TextField(null=True, blank=True)
    occured = models.DateTimeField(null=True, blank=True)
    closed = models.DateTimeField(null=True, blank=True)
    sla = models.IntegerField(null=True, blank=True)
    severity = models.IntegerField(null=True, blank=True)
    investigated_id = models.IntegerField(null=True, blank=True)
    closing_user_id = models.CharField(max_length=255, null=True, blank=True)
    owner = models.CharField(max_length=255, null=True, blank=True)
    playbook_id = models.CharField(max_length=255, null=True, blank=True)
    integration = models.ForeignKey(
        Integration,
        on_delete=models.CASCADE,
        related_name="du_cortex_soar_final_incidents",
        null=True,
        blank=True,
    )
    cortex_soar_tenant = models.ForeignKey(
        DuCortexSOARTenants,
        on_delete=models.CASCADE,
        related_name="du_cortex_soar_final_incidents",
        null=True,
        blank=True,
    )
    # Custom fields
    incident_phase = models.CharField(max_length=100, null=True, blank=True)
    incident_priority = models.CharField(max_length=50, blank=True, null=True)
    incident_tta = models.DateTimeField(blank=True, null=True)
    incident_ttdn = models.DateTimeField(blank=True, null=True)
    incident_ttn = models.DateTimeField(blank=True, null=True)
    initial_notification = models.BooleanField(null=True)

    # JSON Fields
    list_of_rules_offense = models.JSONField(blank=True, null=True)
    log_source_type = models.JSONField(blank=True, null=True)
    low_level_categories_events = models.JSONField(blank=True, null=True)
    source_ips = models.JSONField(blank=True, null=True)

    qradar_category = models.CharField(max_length=100, blank=True, null=True)
    qradar_sub_category = models.CharField(max_length=100, blank=True, null=True)
    tta_calculation = models.CharField(max_length=50, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "du_cortex_soar_final_incidents"
        constraints = [
            models.UniqueConstraint(
                fields=["account", "db_id"], name="unique_account_db_id"
            )
        ]

    def __str__(self):
        return f"{self.incident_id} - {self.name}"


class Company(models.Model):
    company_name = models.CharField(max_length=100, unique=True)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name="companies_created_by"
    )
    qradar_tenant = models.ManyToManyField(DuIbmQradarTenants, blank=True)
    event_collectors = models.ManyToManyField(IBMQradarEventCollector, blank=True)
    integrations = models.ManyToManyField(Integration, blank=True)
    itsm_tenants = models.ManyToManyField(DuITSMTenants, blank=True)
    soar_tenants = models.ManyToManyField(DuCortexSOARTenants, blank=True)
    is_defualt_threat_intel = models.BooleanField(default=True)
    phone_number = models.CharField(max_length=20, blank=True)
    industry = models.CharField(max_length=100, blank=True)
    is_default_sla = models.BooleanField(default=True)
    country = models.CharField(max_length=2, blank=True)
    profile_picture = models.ImageField(
        upload_to="profile_pictures/", blank=True, null=True
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "companies"

    def __str__(self):
        return self.company_name


class Tenant(models.Model):
    company = models.ForeignKey(
        Company, on_delete=models.CASCADE, related_name="tenants"
    )
    tenant = models.ForeignKey(User, on_delete=models.CASCADE)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name="tenants_created_by"
    )
    ldap_group = models.CharField(max_length=100, blank=True)

    country = models.CharField(max_length=2, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class VolumeTypeChoices(models.IntegerChoices):
    EPS = 1, "EPS"
    GB_PER_DAY = 2, "GB/D"


class TenantQradarMapping(models.Model):
    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name="qradar_mappings",
        null=True,
        blank=True,
    )
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    event_collectors = models.ManyToManyField(IBMQradarEventCollector, blank=True)
    contracted_volume_type = models.IntegerField(
        choices=VolumeTypeChoices.choices,
        null=True,
        blank=True,
        help_text="Type of contracted volume: EPS or GB/day",
    )
    contracted_volume = models.FloatField(
        null=True,
        blank=True,
        help_text="Value of contracted volume based on the selected type",
    )

    class Meta:
        unique_together = ("company", "qradar_tenant")


class ThreatIntelligenceTenant(models.Model):
    threat_intelligence = models.IntegerField(
        choices=ThreatIntelligenceSubTypes.choices,
        null=True,
        blank=True,
        help_text="Required for Threat Intelligence Integration type",
        default=ThreatIntelligenceSubTypes.CYWARE,
    )
    access_key = models.CharField(max_length=100, null=True, blank=True)
    secret_key = models.CharField(max_length=100, null=True, blank=True)
    base_url = models.CharField(max_length=100, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    company = models.OneToOneField(
        Company, on_delete=models.CASCADE, related_name="threat_intelligence_tenants"
    )

    class Meta:
        unique_together = ("access_key", "secret_key", "base_url")
        db_table = "cyware_tenants_tool_integration"


class ThreatIntelligenceTenantAlerts(models.Model):
    threat_intelligence = models.ForeignKey(
        ThreatIntelligenceTenant, on_delete=models.CASCADE
    )
    db_id = models.CharField(max_length=64, unique=True)
    title = models.TextField()
    status = models.TextField()
    published_time = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} ({self.db_id})"

    class Meta:
        db_table = "cyware_alerts_tenant"


class CywareTenantTag(models.Model):
    threat_intelligence = models.ForeignKey(
        ThreatIntelligenceTenant, on_delete=models.CASCADE
    )
    db_id = models.UUIDField(unique=True)
    tag_name = models.CharField(max_length=255)
    tag_slug = models.SlugField(max_length=255, unique=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "cyware_tags_tenant"

    def __str__(self):
        return self.tag_name


class CywareTenantGroup(models.Model):
    threat_intelligence = models.ForeignKey(
        ThreatIntelligenceTenant, on_delete=models.CASCADE
    )
    db_id = models.CharField(max_length=64, unique=True)
    group_name = models.CharField(max_length=255)
    group_tlp = models.CharField(max_length=20)
    group_type = models.CharField(max_length=50)
    allowed_for_intel_submission = models.BooleanField(default=False)
    allowed_for_rfi_submission = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "cyware_groups_tenant"

    def __str__(self):
        return self.group_name


class CywareTenantCustomField(models.Model):
    threat_intelligence = models.ForeignKey(
        ThreatIntelligenceTenant, on_delete=models.CASCADE
    )
    db_id = models.CharField(unique=True, max_length=64)
    field_name = models.CharField(max_length=255)
    field_label = models.CharField(max_length=255)
    field_type = models.CharField(max_length=50)
    field_description = models.TextField(blank=True, null=True)
    is_system = models.BooleanField(default=False)  # True = system, False = custom

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "cyware_custom_fields_tenant"

    def __str__(self):
        return self.field_label


class CywareTenantCategories(models.Model):
    threat_intelligence = models.ForeignKey(
        ThreatIntelligenceTenant, on_delete=models.CASCADE
    )
    db_id = models.CharField(max_length=64, unique=True)
    category_name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    threat_indicator_fields = models.ManyToManyField(
        CywareTenantCustomField, related_name="threat_categories_tenant", blank=True
    )
    additional_fields = models.ManyToManyField(
        CywareTenantCustomField, related_name="additional_categories_tenant", blank=True
    )
    required_fields = models.ManyToManyField(
        CywareTenantCustomField, related_name="required_categories_tenant", blank=True
    )

    class Meta:
        db_table = "cyware_categories_tenant"


class CywareTenantAlertDetails(models.Model):
    threat_intelligence = models.ForeignKey(
        ThreatIntelligenceTenant, on_delete=models.CASCADE
    )
    alert = models.ForeignKey(ThreatIntelligenceTenantAlerts, on_delete=models.CASCADE)
    short_id = models.CharField(max_length=64, unique=True)
    title = models.CharField(max_length=512)
    content = models.TextField()
    status = models.CharField(max_length=32)
    tlp = models.CharField(max_length=32)
    published_time = models.DateTimeField(null=True, blank=True)
    push_required = models.BooleanField(default=False)
    push_email_notification = models.BooleanField(default=False)
    tracking_id = models.CharField(max_length=255, null=True, blank=True)

    card_groups = models.ManyToManyField(
        CywareTenantGroup, blank=True, related_name="card_alerts_tenant"
    )
    recipient_groups = models.ManyToManyField(
        CywareTenantGroup, blank=True, related_name="recipient_alerts_tenant"
    )

    card_tag = models.ManyToManyField(
        CywareTenantTag, blank=True, related_name="tagged_alerts_tenant"
    )
    card_category = models.ForeignKey(
        CywareTenantCategories, blank=True, on_delete=models.CASCADE, null=True
    )

    card_image = models.URLField(null=True, blank=True)
    card_info = models.TextField(null=True, blank=True)
    event = models.JSONField(null=True, blank=True)
    intel_id = models.CharField(max_length=255, null=True, blank=True)
    rfi_id = models.CharField(max_length=255, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "cyware_alert_details_tenant"


class Alert(models.Model):
    db_id = models.CharField(max_length=64, unique=True)
    title = models.TextField()
    status = models.TextField()
    published_time = models.DateTimeField(null=True, blank=True)
    integration = models.ForeignKey(
        Integration, on_delete=models.CASCADE, related_name="alerts"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [models.Index(fields=["db_id"])]
        db_table = "cyware_alerts"

    def __str__(self):
        return f"{self.title} ({self.db_id})"


class CywareTag(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    db_id = models.UUIDField(unique=True)
    tag_name = models.CharField(max_length=255)
    tag_slug = models.SlugField(max_length=255, unique=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "cyware_tags"

    def __str__(self):
        return self.tag_name


class CywareGroup(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    db_id = models.CharField(max_length=64, unique=True)
    group_name = models.CharField(max_length=255)
    group_tlp = models.CharField(max_length=20)
    group_type = models.CharField(max_length=50)
    allowed_for_intel_submission = models.BooleanField(default=False)
    allowed_for_rfi_submission = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "cyware_groups"

    def __str__(self):
        return self.group_name


class CywareCustomField(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    db_id = models.CharField(unique=True, max_length=64)
    field_name = models.CharField(max_length=255)
    field_label = models.CharField(max_length=255)
    field_type = models.CharField(max_length=50)
    field_description = models.TextField(blank=True, null=True)
    is_system = models.BooleanField(default=False)  # True = system, False = custom

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "cyware_custom_fields"

    def __str__(self):
        return self.field_label


class CywareCategories(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    db_id = models.CharField(max_length=64, unique=True)
    category_name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    threat_indicator_fields = models.ManyToManyField(
        CywareCustomField, related_name="threat_categories", blank=True
    )
    additional_fields = models.ManyToManyField(
        CywareCustomField, related_name="additional_categories", blank=True
    )
    required_fields = models.ManyToManyField(
        CywareCustomField, related_name="required_categories", blank=True
    )

    class Meta:
        db_table = "cyware_categories"


class CywareAlertDetails(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    alert = models.ForeignKey(Alert, on_delete=models.CASCADE)
    short_id = models.CharField(max_length=64, unique=True)
    title = models.CharField(max_length=512)
    content = models.TextField()
    status = models.CharField(max_length=32)
    tlp = models.CharField(max_length=32)
    published_time = models.DateTimeField(null=True, blank=True)
    push_required = models.BooleanField(default=False)
    push_email_notification = models.BooleanField(default=False)
    tracking_id = models.CharField(max_length=255, null=True, blank=True)

    card_groups = models.ManyToManyField(
        CywareGroup, blank=True, related_name="card_alerts"
    )
    recipient_groups = models.ManyToManyField(
        CywareGroup, blank=True, related_name="recipient_alerts"
    )

    card_tag = models.ManyToManyField(
        CywareTag, blank=True, related_name="tagged_alerts"
    )
    card_category = models.ForeignKey(
        CywareCategories, blank=True, on_delete=models.CASCADE, null=True
    )

    card_image = models.URLField(null=True, blank=True)
    card_info = models.TextField(null=True, blank=True)
    event = models.JSONField(null=True, blank=True)
    intel_id = models.CharField(max_length=255, null=True, blank=True)
    rfi_id = models.CharField(max_length=255, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "cyware_alert_details"


class TenantPermissionChoices(models.IntegerChoices):
    DASHBOARD = 1, "Dashboard"
    CHATBOT = 2, "Chatbot"
    REPORTS = 3, "Reports"
    THREAT_INTELLIGENCE = 4, "Threat Intelligence"
    ASSETS = 5, "Assets"


class TenantRole(models.Model):
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="roles")
    name = models.CharField(max_length=100)

    class TenantRoleChoices(models.IntegerChoices):
        TENANT_ADMIN = 1, "Tenant_ADMIN"
        TENANT_USER = 2, "Tenant_USER"

    role_type = models.IntegerField(
        choices=TenantRoleChoices.choices, default=TenantRoleChoices.TENANT_ADMIN
    )

    class Meta:
        indexes = [models.Index(fields=["tenant"])]

    def __str__(self):
        return f"{self.name} ({self.tenant.tenant.username if self.tenant.tenant else 'Unnamed Tenant'})"


class TenantRolePermissions(models.Model):
    role = models.ForeignKey(
        TenantRole, on_delete=models.CASCADE, related_name="role_permissions"
    )
    permission = models.IntegerField(choices=TenantPermissionChoices.choices)
    permission_text = models.CharField(max_length=100, editable=False)

    def __str__(self):
        return f"{self.role.name} - {self.permission_text}"

    def save(self, *args, **kwargs):
        self.permission_text = TenantPermissionChoices(self.permission).label
        super().save(*args, **kwargs)


class SlaLevelChoices(models.IntegerChoices):
    P1 = 4, "P1 Critical"
    P2 = 3, "P2 High"
    P3 = 2, "P3 Medium"
    P4 = 1, "P4 Low"


class DefaultSoarSlaMetric(models.Model):
    sla_level = models.IntegerField(choices=SlaLevelChoices.choices, unique=True)
    tta_minutes = models.IntegerField(help_text="Time to Acknowledge")
    ttn_minutes = models.IntegerField(help_text="Time to Notify")
    ttdn_minutes = models.IntegerField(help_text="Time to Detection/Neutralization")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "default_soar_sla_metrics"

    def __str__(self):
        return f"Default SLA - {self.get_sla_level_display()}"


class SoarTenantSlaMetric(models.Model):
    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name="soar_sla_metrics",
    )
    soar_tenant = models.ForeignKey(
        DuCortexSOARTenants, on_delete=models.CASCADE, related_name="sla_metrics"
    )

    sla_level = models.IntegerField(choices=SlaLevelChoices.choices)

    tta_minutes = models.PositiveIntegerField(help_text="Time to Acknowledge")
    ttn_minutes = models.PositiveIntegerField(help_text="Time to Notify")
    ttdn_minutes = models.PositiveIntegerField(help_text="Time to Detect/Neutralize")

    class Meta:
        db_table = "soar_tenant_sla_metrics"
        unique_together = ("company", "soar_tenant", "sla_level")

    def __str__(self):
        return f"SLA  - {self.company} - {self.soar_tenant} - {self.get_sla_level_display()}"


class TotalEvents(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    total_events = models.FloatField()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "total_events"
        unique_together = ["qradar_tenant", "integration"]

    def __str__(self):
        return f"{self.qradar_tenant} - {self.integration}"


class EventCountLog(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)

    event_name = models.CharField(max_length=512)
    event_count = models.FloatField()

    created_at = models.DateTimeField(blank=True, null=True, default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "event_count_log"

    def __str__(self):
        return f"{self.event_name} - Count: {self.event_count}"


class ReconEventLog(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    total_recon_events = models.FloatField()

    created_at = models.DateTimeField(blank=True, null=True, default=timezone.now)

    class Meta:
        db_table = "recon_event_log"

    def __str__(self):
        return f"{self.qradar_tenant} - Recon Events: {self.total_recon_events}"


class CorrelatedEventLog(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    correlated_events_count = models.FloatField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "correlated_event_log"

    def __str__(self):
        return (
            f"{self.qradar_tenant} - Correlated Events: {self.correlated_events_count}"
        )


class WeeklyCorrelatedEventLog(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    week = models.CharField(max_length=10)
    weekly_count = models.FloatField()
    created_at = models.DateTimeField(blank=True, null=True, default=timezone.now)

    class Meta:
        db_table = "weekly_correlated_event_log"

    def __str__(self):
        return f"{self.qradar_tenant} - Week {self.week}: {self.weekly_count}"


class SuspiciousEventLog(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    total_suspicious_events = models.FloatField()
    created_at = models.DateTimeField(blank=True, null=True, default=timezone.now)

    class Meta:
        db_table = "suspicious_event_log"

    def __str__(self):
        return (
            f"{self.qradar_tenant} - Suspicious Events: {self.total_suspicious_events}"
        )


class DosEventLog(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    total_dos_events = models.FloatField()
    created_at = models.DateTimeField(blank=True, null=True, default=timezone.now)

    class Meta:
        db_table = "dos_event_log"

    def __str__(self):
        return f"{self.qradar_tenant} - DoS Events: {self.total_dos_events}"


class TopDosEventLog(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    event_name = models.CharField(max_length=255)
    event_count = models.FloatField()
    created_at = models.DateTimeField(blank=True, null=True, default=timezone.now)

    class Meta:
        db_table = "top_dos_event_log"

    def __str__(self):
        return f"{self.qradar_tenant} - {self.event_name}: {self.event_count}"


class DailyEventLog(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    date = models.DateField()
    daily_count = models.FloatField()
    created_at = models.DateTimeField(blank=True, null=True, default=timezone.now)

    class Meta:
        db_table = "daily_event_log"

    def __str__(self):
        return f"{self.qradar_tenant} - {self.date}: {self.daily_count}"


class TopAlertEventLog(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    alert_name = models.CharField(max_length=255)
    event_count = models.FloatField()
    created_at = models.DateTimeField(blank=True, null=True, default=timezone.now)

    class Meta:
        db_table = "top_alert_event_log"

    def __str__(self):
        return f"{self.qradar_tenant} - {self.alert_name}: {self.event_count}"


class DailyClosureReasonLog(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    date = models.DateField()
    closure_reason = models.CharField(max_length=255)
    reason_count = models.FloatField()
    created_at = models.DateTimeField(blank=True, null=True, default=timezone.now)

    class Meta:
        db_table = "daily_closure_reason_log"

    def __str__(self):
        return f"{self.qradar_tenant} - {self.date} - {self.closure_reason}: {self.reason_count}"


class MonthlyAvgEpsLog(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    monthly_avg_eps = models.FloatField()
    created_at = models.DateTimeField(blank=True, null=True, default=timezone.now)

    class Meta:
        db_table = "monthly_avg_eps_log"

    def __str__(self):
        return f"{self.qradar_tenant} - Monthly Avg EPS: {self.monthly_avg_eps}"


class LastMonthAvgEpsLog(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    last_month_avg_eps = models.FloatField()
    created_at = models.DateTimeField(blank=True, null=True, default=timezone.now)

    class Meta:
        db_table = "last_month_avg_eps_log"

    def __str__(self):
        return f"{self.qradar_tenant} - Last Month Avg EPS: {self.last_month_avg_eps}"


class WeeklyAvgEpsLog(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    week = models.CharField(max_length=7)  # Format: yyyy-ww
    week_start = models.CharField(max_length=6)  # Format: dd-MMM
    weekly_avg_eps = models.FloatField()
    created_at = models.DateTimeField(blank=True, null=True, default=timezone.now)

    class Meta:
        db_table = "weekly_avg_eps_log"

    def __str__(self):
        return f"{self.qradar_tenant} - Week {self.week} ({self.week_start}): {self.weekly_avg_eps}"


class TotalTrafficLog(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    total_traffic = models.FloatField()
    created_at = models.DateTimeField(blank=True, null=True, default=timezone.now)

    class Meta:
        db_table = "total_traffic_log"

    def __str__(self):
        return f"{self.qradar_tenant} - Total Traffic: {self.total_traffic}"


class DestinationAddressLog(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    destination_address = models.CharField(max_length=45)  # IPv4/IPv6 address length
    address_count = models.FloatField()
    created_at = models.DateTimeField(blank=True, null=True, default=timezone.now)

    class Meta:
        db_table = "destination_address_log"

    def __str__(self):
        return (
            f"{self.qradar_tenant} - {self.destination_address}: {self.address_count}"
        )


class TopDestinationConnectionLog(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    destination_address = models.CharField(max_length=45)  # IPv4/IPv6 address length
    connection_count = models.FloatField()
    created_at = models.DateTimeField(blank=True, null=True, default=timezone.now)

    class Meta:
        db_table = "top_destination_connection_log"

    def __str__(self):
        return f"{self.qradar_tenant} - {self.destination_address}: {self.connection_count}"


class DailyEventCountLog(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    full_date = models.DateField()
    daily_count = models.FloatField()
    created_at = models.DateTimeField(blank=True, null=True, default=timezone.now)

    class Meta:
        db_table = "daily_event_count_log"

    def __str__(self):
        return f"{self.qradar_tenant} - {self.full_date}: {self.daily_count}"


class ChatMessage(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE)
    admin = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="admin_chats"
    )
    tenant = models.ForeignKey(
        Tenant, on_delete=models.CASCADE, related_name="tenant_chats"
    )
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "chat_service"


class SuccessfulLogonEvent(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    username = models.CharField(max_length=255)
    logon_type = models.TextField()
    source_ip = models.CharField(max_length=45)
    log_source = models.CharField(max_length=255)
    event_count = models.FloatField()
    full_date = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "successful_logon_events"
        indexes = [
            models.Index(fields=["username"]),
            models.Index(fields=["source_ip"]),
            models.Index(fields=["full_date"]),
        ]

    def __str__(self):
        return f"{self.username} - {self.source_ip} - {self.event_count}"


class RemoteUsersCount(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    total_remote_users = models.FloatField()
    full_date = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "remote_users_count"
        verbose_name_plural = "Remote Users Counts"

    def __str__(self):
        return f"{self.qradar_tenant} - {self.full_date}: {self.total_remote_users}"


class SourceIPGeoLocation(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    source_ip = models.GenericIPAddressField()
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    geo_type = models.CharField(max_length=50, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "source_ip_geolocations"

    def __str__(self):
        return f"{self.source_ip} - ({self.latitude}, {self.longitude})"


class DUSoarNotes(models.Model):
    db_id = models.IntegerField(unique=True)
    category = models.CharField(max_length=255, null=True, blank=True)
    content = models.TextField(null=True, blank=True)
    created = models.DateTimeField(null=True, blank=True)
    user = models.CharField(max_length=255, null=True, blank=True)

    # Foreign key or reference fields
    incident = models.ForeignKey(
        DUCortexSOARIncidentFinalModel, on_delete=models.CASCADE, null=True, blank=True
    )
    integration = models.ForeignKey(
        Integration, on_delete=models.CASCADE, null=True, blank=True
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "notes"

    def __str__(self):
        return f"{self.user} - {self.category} ({self.created})"
