import time

from celery import shared_task
from loguru import logger

from common.modules.fortisoar import FortiSOAR
from integration.models import (
    CredentialTypes,
    IntegrationCredentials,
    IntegrationTypes,
    SoarSubTypes,
)
from tenant.models import DUFortiSOARTenants


@shared_task
def sync_forti_soar_tenants(token: str, ip_address: str, port, integration_id: int):
    logger.info("Running sync_forti_soar_tenants() task")
    start = time.time()
    try:
        with FortiSOAR(ip_address, port, token) as fsoar:
            data = fsoar._get_tenants()
            if not data.get("hydra:member"):
                return
            transformed_data = fsoar.transform_tenants(data, integration_id)
            if not transformed_data:
                return

            fsoar._insert_tenants(transformed_data)
            logger.info(f"Successfully synced {len(transformed_data)} tenants")
    except Exception as e:
        logger.error(f"Error sync_forti_soar_tenants: {e}")

    logger.info(
        f"FortiSOARTenants.sync_forti_soar_tenants() task took {time.time() - start} seconds"
    )


@shared_task
def sync_forti_soar_alert_for_tenant(
    forti_soar_tenant_id,
    forti_soar_tenant_name,
    ip_address,
    port,
    api_key,
    integration_id,
):
    logger.info(f"Running sync_forti_soar_alerts for tenant {forti_soar_tenant_name}")
    with FortiSOAR(
        ip_address=ip_address,
        port=port,
        token=api_key,
    ) as fsoar:
        if forti_soar_tenant_name == "CDC-Mey-Test":
            return
        data = fsoar._get_alerts(tenant_name=forti_soar_tenant_name)
        if not data:
            logger.warning(f"No alerts found for tenant {forti_soar_tenant_name}")
            return
        transformed_data = fsoar.transform_alerts(
            data=data,
            integration_id=integration_id,
            forti_soar_tenant_id=forti_soar_tenant_id,
            name=forti_soar_tenant_name,
        )
        logger.info(
            f"Transformed {len(transformed_data)} alerts for tenant {forti_soar_tenant_name}"
        )
        fsoar._insert_alerts(transformed_data)


@shared_task
def sync_forti_soar_alerts():
    logger.info("Running sync_forti_soar_alerts() task")
    time.time()
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SOAR_INTEGRATION,
        integration__soar_subtype=SoarSubTypes.FORTI_SOAR,
        credential_type=CredentialTypes.API_KEY,
    )

    for integration in results:
        forti_soar_tenants = DUFortiSOARTenants.objects.filter(
            integration=integration.id
        ).all()
        for forti_soar_tenant in forti_soar_tenants:
            kwargs = {
                "forti_soar_tenant_id": forti_soar_tenant.id,
                "forti_soar_tenant_name": forti_soar_tenant.name,
                "ip_address": integration.ip_address,
                "port": integration.port,
                "api_key": integration.api_key,
                "integration_id": integration.integration.id,
            }
            sync_forti_soar_alert_for_tenant.delay(**kwargs)


@shared_task
def sync_forti_soar_data():
    logger.info("Running sync_forti_soar_data() task")
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SOAR_INTEGRATION,
        integration__soar_subtype=SoarSubTypes.FORTI_SOAR,
        credential_type=CredentialTypes.API_KEY,
    )
    for result in results:
        sync_forti_soar_tenants(
            token=result.api_key,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )
        sync_forti_soar_alerts()
