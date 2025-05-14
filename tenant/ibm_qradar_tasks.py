import time

from celery import shared_task
from loguru import logger

from common.modules.ibm_qradar import IBMQradar
from common.modules.itsm import ITSM


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
