import time

from celery import shared_task
from loguru import logger

from common.modules.ibm_qradar import IBMQradar


class QRadarTasks:
    @staticmethod
    @shared_task
    def sync_qradar_tenants(username, password):
        """
        Celery task to fetch QRadar tenants data from an endpoint every 30 minutes
        and sync it into the du_ibm_qradar_tenants table using IBMQRadar's _insert_domains method.
        """
        start = time.time()
        logger.info("Running QRadarTasks.sync_qradar_tenants() task")
        try:
            # Fetch data from the endpoint and transform it
            with IBMQradar(username=username, password=password) as ibm_qradar:
                data = ibm_qradar._get_domains()
                if data is None:
                    logger.error("No data returned from IBM QRadar domains endpoint")
                    return

                # Transform the data into the required format
                transformed_data = ibm_qradar._transform_domains(data)

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

    @staticmethod
    @shared_task
    def sync_event_collectors(username, password):
        start = time.time()
        logger.info("Running QRadarTasks.sync_event_collectors() task")
        try:
            with IBMQradar(username=username, password=password) as ibm_qradar:
                data = ibm_qradar._get_event_collectors()
                if data is None:
                    logger.error(
                        "No data returned from IBM QRadar event collectors endpoint"
                    )
                    return

                transformed_data = ibm_qradar._transform_event_collectors(data)

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
