import time

from celery import shared_task
from loguru import logger

from common.modules.itsm import ITSM
from integration.models import (
    CredentialTypes,
    IntegrationCredentials,
    IntegrationTypes,
    ItsmSubTypes,
)
from tenant.models import DuITSMTenants


@shared_task
def sync_itsm_tenants(auth_token: str, ip_address: str, port: int, integration_id: int):
    """
    Syncs the ITSM tenants with the database.

    This task fetches the accounts from the ITSM instance and
    inserts them into the database.

    :param auth_token: The authentication token to use when logging into the ITSM.
    :param ip_address: The IP address of the ITSM instance.
    :param port: The port to use when connecting to the ITSM instance.
    :param integration_id: The ID of the integration for which to sync the tenants.
    """

    start = time.time()
    try:
        with ITSM(ip_address=ip_address, port=port, token=auth_token) as itsm:
            accounts = itsm._get_accounts()
            if accounts is None:
                logger.error("No data returned from ITSM accounts endpoint")
                return

            transformed_data = itsm._transform_accounts(
                accounts=accounts, integration_id=integration_id
            )
            if not isinstance(transformed_data, list):
                logger.error("Invalid data format: Expected a list")
                return

            itsm._insert_accounts(transformed_data)

            logger.info(f"Successfully synced {len(transformed_data)} ITSM tenants")
            logger.info(
                f"ITSMTasks.sync_itsm_tenants() task took {time.time() - start} seconds"
            )
    except Exception as e:
        logger.error(f"Unexpected error in sync_itsm_tenants: {str(e)}")


@shared_task
def sync_itsm_tenants_cron():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.ITSM_INTEGRATION,
        integration__itsm_subtype=ItsmSubTypes.MANAGE_ENGINE,
        credential_type=CredentialTypes.API_KEY,
    )

    for result in results:
        with ITSM(
            ip_address=result.ip_address, port=result.port, token=result.api_key
        ) as itsm:
            data = itsm._get_accounts()
            if not data:
                logger.warning(
                    f"No data returned from ITSM accounts endpoint for integration {result.integration.id}"
                )

            transformed_data = itsm._transform_accounts(
                accounts=data, integration_id=result.integration.id
            )
            itsm._insert_accounts(transformed_data)


@shared_task
def sync_itsm_tenants_tickets():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.ITSM_INTEGRATION,
        integration__itsm_subtype=ItsmSubTypes.MANAGE_ENGINE,
        credential_type=CredentialTypes.API_KEY,
    )

    for result in results:
        with ITSM(
            ip_address=result.ip_address, port=result.port, token=result.api_key
        ) as itsm:
            itsm_tenants = DuITSMTenants.objects.filter(
                integration=result.integration
            ).all()
            for tenant in itsm_tenants:
                data = itsm._get_requests(account_id=tenant.db_id)
                if not data:
                    logger.warning(
                        f"No data returned from ITSM accounts endpoint for integration {result.integration.id}"
                    )
                transformed_data = itsm.transform_tickets(
                    data=data, integration_id=result.integration.id, tenant_id=tenant.id
                )
                itsm.insert_tickets(tickets=transformed_data)


@shared_task
def sync_itsm():
    logger.info("Running ITSMTasks.sync_itsm() task")
    logger.info("Running sync_itsm_tenants_cron() task")
    sync_itsm_tenants_cron.delay()
    logger.info("Running sync_itsm_tenants_tickets() task")
    sync_itsm_tenants_tickets.delay()
