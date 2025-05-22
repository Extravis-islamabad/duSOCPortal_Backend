import time

from celery import shared_task
from loguru import logger

from common.modules.ibm_qradar import IBMQradar
from integration.models import (
    CredentialTypes,
    IntegrationCredentials,
    IntegrationTypes,
    SiemSubTypes,
)


@shared_task
def sync_qradar_tenants(
    username: str, password: str, ip_address: str, port: int, integration_id: int
):
    """
    Syncs the QRadar tenants with the database.

    This task fetches the domains (tenants) from the IBM QRadar instance and
    inserts them into the database.

    :param username: The username to use when logging into the QRadar.
    :param password: The password to use when logging into the QRadar.
    :param ip_address: The IP address of the QRadar instance.
    :param port: The port to use when connecting to the QRadar instance.
    :param integration_id: The ID of the integration for which to sync the tenants.
    """
    start = time.time()
    logger.info("Running QRadarTasks.sync_qradar_tenants() task")
    try:
        # Fetch data from the endpoint and transform it
        with IBMQradar(
            username=username, password=password, ip_address=ip_address, port=port
        ) as ibm_qradar:
            data = ibm_qradar._get_domains()
            if data is None:
                logger.error("No data returned from IBM QRadar domains endpoint")
                return

            # Transform the data into the required format
            transformed_data = ibm_qradar._transform_domains(
                data, integration_id=integration_id
            )

        if not isinstance(transformed_data, list):
            logger.error("Invalid data format: Expected a list")
            return

        ibm_qradar._insert_domains(transformed_data)

        logger.info(f"Successfully synced {len(transformed_data)} QRadar tenants")
        logger.info(
            f"QRadarTasks.sync_qradar_tenants() task took {time.time() - start} seconds"
        )
    except Exception as e:
        logger.error(f"Unexpected error in sync_qradar_tenants: {str(e)}")


@shared_task
def sync_event_collectors(
    username: str, password: str, ip_address: str, port: str, integration_id: int
):
    """
    Syncs the event collectors for a given QRadar integration.

    :param username: The username to use when logging into the QRadar.
    :param password: The password to use when logging into the QRadar.
    :param ip_address: The IP address of the QRadar instance.
    :param port: The port to use when connecting to the QRadar instance.
    :param integration_id: The ID of the integration for which to sync the event collectors.
    """

    start = time.time()
    logger.info("Running QRadarTasks.sync_event_collectors() task")
    try:
        with IBMQradar(
            username=username, password=password, ip_address=ip_address, port=port
        ) as ibm_qradar:
            data = ibm_qradar._get_event_collectors()
            if data is None:
                logger.error(
                    "No data returned from IBM QRadar event collectors endpoint"
                )
                return

            transformed_data = ibm_qradar._transform_event_collectors(
                data, integration_id=integration_id
            )

        if not isinstance(transformed_data, list):
            logger.error("Invalid data format: Expected a list")
            return

        ibm_qradar._insert_event_collectors(transformed_data)

        logger.info(f"Successfully synced {len(transformed_data)} event collectors")
        logger.info(
            f"QRadarTasks.sync_event_collectors() task took {time.time() - start} seconds"
        )
    except Exception as e:
        logger.error(f"Unexpected error in sync_event_collectors: {str(e)}")


@shared_task
def sync_event_log_assets(
    username: str, password: str, ip_address: str, port: str, integration_id: int
):
    start = time.time()
    logger.info("Running QRadarTasks.sync_event_log_assets() task")
    try:
        with IBMQradar(
            username=username, password=password, ip_address=ip_address, port=port
        ) as ibm_qradar:
            data = ibm_qradar._get_event_logs()
            if data is None:
                logger.error(
                    "No data returned from IBM QRadar event log assets endpoint"
                )
                return

            transformed_data = ibm_qradar._transform_event_logs(
                data, integration_id=integration_id
            )

        if not isinstance(transformed_data, list):
            logger.error("Invalid data format: Expected a list")
            return

        ibm_qradar._insert_event_logs(transformed_data)

        logger.info(f"Successfully synced {len(transformed_data)} event log assets")
        logger.info(
            f"QRadarTasks.sync_event_log_assets() task took {time.time() - start} seconds"
        )
    except Exception as e:
        logger.error(f"Unexpected error in sync_event_log_assets: {str(e)}")


@shared_task
def sync_event_log_sources():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        with IBMQradar(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
        ) as ibm_qradar:
            data = ibm_qradar._get_offenses()
            if not data:
                logger.warning(
                    f"No data returned from IBM QRadar offenses endpoint for integration {result.integration.id}"
                )
            transformed_data, _ = ibm_qradar._transform_offenses(
                data=data, integration_id=result.integration.id
            )
            if transformed_data:
                ibm_qradar._insert_offenses(transformed_data)
        # sync_event_log_assets(
        #     result.username,
        #     result.password,
        #     result.ip_address,
        #     result.port,
        #     result.integration.id,
        # )

    print(results)
