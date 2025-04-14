from django.db import models

from tenant.models import Tenant


class IntegrationTypes(models.IntegerChoices):
    SIEM_INTEGRATION = 1, "SIEM Integration"
    SOAR_INTEGRATION = 2, "SOAR Integration"
    ITSM_INTEGRATION = 3, "ITSM Integration"


class Integration(models.Model):
    integration_type = models.IntegerField(
        choices=IntegrationTypes.choices, default=IntegrationTypes.SIEM_INTEGRATION
    )
    tenant = models.ForeignKey(
        Tenant, on_delete=models.CASCADE, related_name="integrations"
    )
    instance_name = models.CharField(max_length=100)
    instance_type = models.CharField(max_length=100)
    api_key = models.CharField(max_length=100)
    version = models.CharField(max_length=100)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.instance_name
