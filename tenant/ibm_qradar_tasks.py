import time

from celery import shared_task
from django.db import transaction
from loguru import logger

from common.modules.ibm_qradar import IBMQradar


class QRadarTasks:
    @staticmethod
    @shared_task
    def sync_qradar_tenants():
        """
        Celery task to fetch QRadar tenants data from an endpoint every 30 minutes
        and sync it into the du_ibm_qradar_tenants table using IBMQRadar's _insert_domains method.
        """
        start = time.time()
        logger.info("Running QRadarTasks.sync_qradar_tenants() task")
        try:
            # Fetch data from the endpoint and transform it
            with IBMQradar() as ibm_qradar:
                data = ibm_qradar._get_domains()
                if data is None:
                    logger.error("No data returned from IBM QRadar domains endpoint")
                    return

                # Transform the data into the required format
                transformed_data = ibm_qradar._transform_domains(data)

            if not isinstance(transformed_data, list):
                logger.error("Invalid data format: Expected a list")
                return

            # Use a transaction to ensure atomicity
            with transaction.atomic():
                # Insert or update the domains using IBMQRadar's _insert_domains
                ibm_qradar._insert_domains(transformed_data)

            logger.info(f"Successfully synced {len(transformed_data)} QRadar tenants")
            logger.info(
                f"QRadarTasks.sync_qradar_tenants() task took {time.time() - start} seconds"
            )
        except Exception as e:
            logger.error(f"Unexpected error in sync_qradar_tenants: {str(e)}")
