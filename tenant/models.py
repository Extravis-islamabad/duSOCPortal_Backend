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
    event_collector_id = models.ForeignKey(
        IBMQradarEventCollector,
        on_delete=models.CASCADE,
        related_name="du_ibm_qradar_assets",
        null=True,
        blank=True,
    )
    average_eps = models.IntegerField(default=0)
    creation_date = models.CharField(max_length=255, blank=True, default=None)
    modified_date = models.CharField(max_length=255, blank=True, default=None)
    last_event_time = models.CharField(max_length=255, blank=True, default=None)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "du_ibm_qradar_assets"


class DuITSMTenants(models.Model):
    id = models.AutoField(primary_key=True)
    db_id = models.IntegerField(unique=True)
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
