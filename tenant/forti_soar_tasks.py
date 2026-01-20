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


@shared_task
def sync_forti_soar_tenants(token, ip_address, port, integration_id):
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
