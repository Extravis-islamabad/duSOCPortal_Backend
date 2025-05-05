import time

from celery import shared_task
from django.db import transaction
from loguru import logger

from common.modules.ibm_qradar import IBMQradar
from tenant.models import DuIbmQradarTenants


class QRadarTasks:
    @staticmethod
    @shared_task
    def sync_qradar_tenants():
        """
        Celery task to fetch QRadar tenants data from an endpoint every 30 minutes
        and sync it into the du_ibm_qradar_tenants table.
        """
        start = time.time()
        logger.info("Running QRadarTasks.sync_qradar_tenants() task")
        try:
            # Fetch data from the endpoint
            with IBMQradar() as ibm_qradar:
                data = ibm_qradar._get_domains()
                if data is None:
                    return
            if not isinstance(data, list):
                logger.error("Invalid data format: Expected a list")
                return

            # Use a transaction to ensure atomicity
            with transaction.atomic():
                for item in data:
                    db_id = item.get("id")
                    name = item.get("name", "")

                    # Validate required fields
                    if db_id is None:
                        logger.warning(f"Skipping record with missing id: {item}")
                        continue

                    DuIbmQradarTenants.objects.update_or_create(
                        db_id=db_id, defaults={"name": name}
                    )

            logger.info(f"Successfully synced {len(data)} QRadar tenants")
            logger.info(
                f"QRadarTasks.sync_qradar_tenants() task took {time.time() - start} seconds"
            )
        except Exception as e:
            logger.error(f"Unexpected error in sync_qradar_tenants: {str(e)}")
