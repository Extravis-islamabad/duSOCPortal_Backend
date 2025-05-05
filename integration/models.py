from django.db import models
from django.forms import ValidationError

from tenant.models import Tenant


class IntegrationTypes(models.IntegerChoices):
    SIEM_INTEGRATION = 1, "SIEM Integration"
    SOAR_INTEGRATION = 2, "SOAR Integration"
    ITSM_INTEGRATION = 3, "ITSM Integration"


class SiemSubTypes(models.IntegerChoices):
    IBM_QRADAR = 1, "IBM QRadar"
    SPLUNK = 2, "Splunk"
    OTHER = 3, "Other"


class SoarSubTypes(models.IntegerChoices):
    SERVICENOW = 1, "ServiceNow"
    IBM_RESILIENT = 2, "IBM Resilient"
    OTHER = 3, "Other"


class ItsmSubTypes(models.IntegerChoices):
    JIRA = 1, "Jira"
    ZENDESK = 2, "Zendesk"
    OTHER = 3, "Other"


class Integration(models.Model):
    integration_type = models.IntegerField(
        choices=IntegrationTypes.choices, default=IntegrationTypes.SIEM_INTEGRATION
    )
    tenant = models.ForeignKey(
        Tenant, on_delete=models.CASCADE, related_name="integrations"
    )
    siem_subtype = models.IntegerField(
        choices=SiemSubTypes.choices,
        null=True,
        blank=True,
        help_text="Required for SIEM Integration type",
    )
    soar_subtype = models.IntegerField(
        choices=SoarSubTypes.choices,
        null=True,
        blank=True,
        help_text="Required for SOAR Integration type",
    )
    itsm_subtype = models.IntegerField(
        choices=ItsmSubTypes.choices,
        null=True,
        blank=True,
        help_text="Required for ITSM Integration type",
    )
    instance_name = models.CharField(max_length=100)
    instance_type = models.CharField(max_length=100)
    api_key = models.CharField(max_length=100)
    version = models.CharField(max_length=100)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.instance_name

    def clean(self):
        """Validate that the correct subtype is set based on integration_type."""
        if self.integration_type == IntegrationTypes.SIEM_INTEGRATION:
            if not self.siem_subtype:
                raise ValidationError(
                    {
                        "siem_subtype": "SIEM subtype is required for SIEM Integration type."
                    }
                )
            self.soar_subtype = None
            self.itsm_subtype = None
        elif self.integration_type == IntegrationTypes.SOAR_INTEGRATION:
            if not self.soar_subtype:
                raise ValidationError(
                    {
                        "soar_subtype": "SOAR subtype is required for SOAR Integration type."
                    }
                )
            self.siem_subtype = None
            self.itsm_subtype = None
        elif self.integration_type == IntegrationTypes.ITSM_INTEGRATION:
            if not self.itsm_subtype:
                raise ValidationError(
                    {
                        "itsm_subtype": "ITSM subtype is required for ITSM Integration type."
                    }
                )
            self.siem_subtype = None
            self.soar_subtype = None

    def save(self, *args, **kwargs):
        """Ensure clean is called before saving."""
        self.full_clean()
        super().save(*args, **kwargs)


class DuIbmQradarTenants(models.Model):
    id = models.AutoField(primary_key=True)
    db_id = models.IntegerField(unique=True)
    name = models.CharField(max_length=255, blank=True, default="")

    class Meta:
        db_table = "du_ibm_qradar_tenants"

    def __str__(self):
        return self.name
