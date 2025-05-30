from django.db import models

from authentication.models import User
from integration.models import Integration


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

    class Meta:
        db_table = "du_ibm_qradar_assets"


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

    class Meta:
        db_table = "du_ibm_qradar_offenses"

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
    db_id = models.IntegerField(unique=True, null=True, blank=True)
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

    class Meta:
        db_table = "du_cortex_soar_final_incidents"

    def __str__(self):
        return f"{self.incident_id} - {self.name}"


class Tenant(models.Model):
    tenant = models.ForeignKey(User, on_delete=models.CASCADE)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name="created_tenants"
    )
    qradar_tenants = models.ManyToManyField(DuIbmQradarTenants, blank=True)
    event_collectors = models.ManyToManyField(IBMQradarEventCollector, blank=True)
    integrations = models.ManyToManyField(Integration, blank=True)
    itsm_tenants = models.ManyToManyField(DuITSMTenants, blank=True)
    soar_tenants = models.ManyToManyField(DuCortexSOARTenants, blank=True)
    phone_number = models.CharField(max_length=20, blank=True)
    country = models.CharField(max_length=2, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class TenantQradarMapping(models.Model):
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    qradar_tenant = models.ForeignKey(DuIbmQradarTenants, on_delete=models.CASCADE)
    event_collectors = models.ManyToManyField(IBMQradarEventCollector, blank=True)

    class Meta:
        unique_together = ("tenant", "qradar_tenant")


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
        TENANT_ADMIN = 1, "Tenant"

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
