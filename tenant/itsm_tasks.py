import time

from celery import shared_task
from loguru import logger

from common.modules.itsm import ITSM


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


# @shared_task
# def sync_itsm_tenants_test(
#     auth_token: str, ip_address: str, port: int, integration_id: int
# ):
#     """
#     Syncs the ITSM tenants with the database.

#     This task fetches the accounts from the ITSM instance and
#     inserts them into the database.

#     :param auth_token: The authentication token to use when logging into the ITSM.
#     :param ip_address: The IP address of the ITSM instance.
#     :param port: The port to use when connecting to the ITSM instance.
#     :param integration_id: The ID of the integration for which to sync the tenants.
#     """

#     start = time.time()
#     try:
#         with ITSM(ip_address=ip_address, port=port, token=auth_token) as itsm:
#             accounts = itsm._get_accounts_test()
#             if accounts is None:
#                 logger.error("No data returned from ITSM accounts endpoint")
#                 return

#             transformed_data = itsm._transform_accounts(
#                 accounts=accounts, integration_id=integration_id
#             )
#             if not isinstance(transformed_data, list):
#                 logger.error("Invalid data format: Expected a list")
#                 return

#             itsm._insert_accounts(transformed_data)

#             logger.info(f"Successfully synced {len(transformed_data)} ITSM tenants")
#             logger.info(
#                 f"ITSMTasks.sync_itsm_tenants() task took {time.time() - start} seconds"
#             )
#     except Exception as e:
#         logger.error(f"Unexpected error in sync_itsm_tenants: {str(e)}")
