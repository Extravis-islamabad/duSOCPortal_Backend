from celery import shared_task

from common.modules.cyware import Cyware
from integration.models import (
    CredentialTypes,
    IntegrationCredentials,
    IntegrationTypes,
    ThreatIntelligenceSubTypes,
)
from tenant.models import Alert, ThreatIntelligenceTenant


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
def sync_threat_groups():
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
            groups = cyware.get_list_groups()
            transformed_data = cyware.transform_groups(
                data=groups, integration=result.integration.id
            )
            cyware.insert_groups(groups=transformed_data)


@shared_task
def sync_threat_custom_fields():
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
            custom_fields = cyware.get_custom_fields()
            transformed_data = cyware.transform_custom_fields(
                data=custom_fields, integration=result.integration.id
            )
            cyware.insert_custom_fields(fields=transformed_data)


@shared_task
def sync_threat_categories():
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
            categories = cyware.get_categories()
            transformed_data = cyware.transform_categories(
                data=categories, integration=result.integration.id
            )
            cyware.insert_categories(categories=transformed_data)


@shared_task
def sync_threat_alert_details():
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
            alerts = (
                Alert.objects.filter(integration=result.integration)
                .all()
                .order_by("-created_at")
            )
            for alert in alerts:
                data = cyware.get_alert_detail(short_id=alert.db_id)
                alert_object = cyware.transform_alert_detail(
                    data=data, integration_id=result.integration.id, alert_id=alert.id
                )
                cyware.insert_alert_detail(alert_obj=alert_object)


@shared_task
def sync_threat_intel_for_tenants():
    results = ThreatIntelligenceTenant.objects.all().order_by("-created_at").first()
    if not results:
        return

    if isinstance(results, ThreatIntelligenceTenant):
        results = [results]

    for result in results:
        with Cyware(
            access_key=result.access_key,
            secret_key=result.secret_key,
            base_url=result.base_url,
        ) as cyware:
            all_alerts = cyware.fetch_all_alerts(page_size=1000)
            transformed_data = cyware.transform_alert_for_tenants(all_alerts, result.id)
            cyware.insert_tenant_alerts(transformed_data)


@shared_task
def sync_threat_intel_tags_for_tenants():
    results = ThreatIntelligenceTenant.objects.all().order_by("-created_at").first()
    if not results:
        return

    if isinstance(results, ThreatIntelligenceTenant):
        results = [results]

    for result in results:
        with Cyware(
            access_key=result.access_key,
            secret_key=result.secret_key,
            base_url=result.base_url,
        ) as cyware:
            tags = cyware.get_list_tags()
            transformed_data = cyware.transform_tags_for_tenants(
                data=tags, threat_intel_id=result.id
            )
            cyware.insert_tags_for_tenants(tags=transformed_data)


@shared_task
def sync_threat_intel_groups_for_tenants():
    results = ThreatIntelligenceTenant.objects.all().order_by("-created_at").first()
    if not results:
        return

    if isinstance(results, ThreatIntelligenceTenant):
        results = [results]

    for result in results:
        with Cyware(
            access_key=result.access_key,
            secret_key=result.secret_key,
            base_url=result.base_url,
        ) as cyware:
            groups = cyware.get_list_groups()
            transformed_data = cyware.transform_groups_for_tenants(
                data=groups, threat_intel_id=result.id
            )
            cyware.insert_groups_for_tenants(groups=transformed_data)


@shared_task
def sync_threat_intel_custom_fields_for_tenants():
    results = ThreatIntelligenceTenant.objects.all().order_by("-created_at").first()
    if not results:
        return

    if isinstance(results, ThreatIntelligenceTenant):
        results = [results]

    for result in results:
        with Cyware(
            access_key=result.access_key,
            secret_key=result.secret_key,
            base_url=result.base_url,
        ) as cyware:
            custom_fields = cyware.get_custom_fields()
            transformed_data = cyware.transform_custom_fields_for_tenants(
                data=custom_fields, threat_intel_id=result.id
            )
            cyware.insert_custom_fields_for_tenants(fields=transformed_data)


@shared_task
def sync_threat_intel_all():
    sync_threat_intel.delay()
    sync_threat_tags.delay()
    sync_threat_groups.delay()
    sync_threat_custom_fields.delay()
    sync_threat_categories.delay()
    sync_threat_alert_details.delay()
    sync_threat_intel_for_tenants.delay()
