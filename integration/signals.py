# integrations/signals.py

from django.db.models.signals import post_save
from django.dispatch import receiver

from tenant.ibm_qradar_tasks import sync_event_collectors, sync_qradar_tenants

from .models import (
    CredentialTypes,
    IntegrationCredentials,
    IntegrationTypes,
    SiemSubTypes,
)


@receiver(post_save, sender=IntegrationCredentials)
def trigger_integration_tasks(
    sender, instance: IntegrationCredentials, created, **kwargs
):
    """
    Trigger IBM QRadar integration tasks when a new IntegrationCredentials object is created.
    If the integration type is SIEM and subtype is IBM QRadar, trigger the tasks to sync
    tenants and event collectors.
    """
    if created:
        if instance.integration.integration_type == IntegrationTypes.SIEM_INTEGRATION:
            if instance.integration.siem_subtype == SiemSubTypes.IBM_QRADAR:
                if instance.credential_type == CredentialTypes.USERNAME_PASSWORD:
                    username = instance.username
                    password = getattr(instance, "_plaintext_password", None)
                    ip_address = instance.ip_address
                    port = instance.port

                    kwargs = {
                        "username": username,
                        "password": password,
                        "ip_address": ip_address,
                        "port": port,
                        "integration_id": instance.integration.id,
                    }
                    sync_qradar_tenants.delay(**kwargs)
                    sync_event_collectors.delay(**kwargs)
