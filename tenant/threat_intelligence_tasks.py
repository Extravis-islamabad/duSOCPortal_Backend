from celery import shared_task

from common.modules.cyware import Cyware
from integration.models import (
    CredentialTypes,
    IntegrationCredentials,
    IntegrationTypes,
    ThreatIntelligenceSubTypes,
)
from tenant.models import ThreatIntelligenceTenant


@shared_task
def sync_threat_intel():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.THREAT_INTELLIGENCE,
        integration__threat_intelligence_subtype=ThreatIntelligenceSubTypes.CYWARE,
        credential_type=CredentialTypes.SECRET_KEY_ACCESS_KEY,
    )

    for result in results:
        with Cyware(
            access_key=result.access_key,
            secret_key=result.secret_key,
            base_url=result.base_url,
        ) as cyware:
            all_alerts = cyware.fetch_all_alerts(page_size=1000)
            transformed_data = cyware.transform_alert(all_alerts, result.integration.id)
            cyware.insert_alerts(transformed_data)


@shared_task
def sync_threat_intel_with_signal(access_key, secret_key, base_url, integration_id):
    with Cyware(
        access_key=access_key, secret_key=secret_key, base_url=base_url
    ) as cyware:
        all_alerts = cyware.fetch_all_alerts(page_size=1000)
        transformed_data = cyware.transform_alert(all_alerts, integration_id)
        cyware.insert_alerts(transformed_data)


@shared_task
def sync_threat_tags():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.THREAT_INTELLIGENCE,
        integration__threat_intelligence_subtype=ThreatIntelligenceSubTypes.CYWARE,
        credential_type=CredentialTypes.SECRET_KEY_ACCESS_KEY,
    )

    for result in results:
        with Cyware(
            access_key=result.access_key,
            secret_key=result.secret_key,
            base_url=result.base_url,
        ) as cyware:
            tags = cyware.get_list_tags()
            transformed_data = cyware.transform_tags(
                data=tags, integration=result.integration.id
            )
            cyware.insert_tags(tags=transformed_data)


@shared_task
def sync_threat_intel_for_tenants():
    results = ThreatIntelligenceTenant.objects.all()

    for result in results:
        with Cyware(
            access_key=result.access_key,
            secret_key=result.secret_key,
            base_url=result.base_url,
        ) as cyware:
            all_alerts = cyware.fetch_all_alerts(page_size=1000)
            transformed_data = cyware.transform_alert_for_tenants(all_alerts, result.id)
            cyware.insert_tenant_alerts(transformed_data)
