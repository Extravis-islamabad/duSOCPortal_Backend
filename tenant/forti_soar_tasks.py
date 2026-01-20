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
    except Exception as e:
        logger.error(f"Error sync_forti_soar_tenants: {e}")
    logger.info(f"Successfully synced {len(transformed_data)} tenants")
    logger.info(
        f"FortiSOARTenants.sync_forti_soar_tenants() task took {time.time() - start} seconds"
    )


@shared_task
def sync_forti_soar_alerts():
    logger.info("Running sync_forti_soar_alerts() task")
    start = time.time()
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SOAR_INTEGRATION,
        integration__soar_subtype=SoarSubTypes.FORTI_SOAR,
        credential_type=CredentialTypes.API_KEY,
    )

    for integration in results:
        forti_soar_tenants = DUFortiSOARTenants.objects.filter(
            integration=integration.id
        ).all()
        try:
            with FortiSOAR(
                ip_address=integration.ip_address,
                port=integration.port,
                token=integration.api_key,
            ) as fsoar:
                for forti_soar_tenant in forti_soar_tenants:
                    logger.info(
                        f"Running sync_forti_soar_alerts for tenant {forti_soar_tenant.name}"
                    )
                    data = fsoar._get_alerts(tenant_name=forti_soar_tenant.name)
                    if not data:
                        logger.warning(
                            f"No alerts found for tenant {forti_soar_tenant.name}"
                        )
                        continue
                    transformed_data = fsoar.transform_alerts(
                        data=data,
                        integration_id=integration.integration,
                        forti_soar_tenant_id=forti_soar_tenant,
                        name=forti_soar_tenant.name,
                    )
                    logger.info(
                        f"Transformed {len(transformed_data)} alerts for tenant {forti_soar_tenant.name}"
                    )
                    fsoar._insert_alerts(transformed_data)
        except Exception as e:
            logger.error(f"Error sync_forti_soar_alerts: {e}")
        logger.info(f"Successfully synced {len(transformed_data)} alerts")
        logger.info(
            f"FortiSOARAlerts.sync_forti_soar_alerts() task took {time.time() - start} seconds"
        )


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
