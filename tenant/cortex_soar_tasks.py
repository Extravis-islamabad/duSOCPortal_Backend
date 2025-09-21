import re
import time
from datetime import date

from celery import shared_task
from django.db.models import Count
from loguru import logger

from common.modules.cortex_soar import CortexSOAR
from common.utils import DateTimeStorage
from integration.models import (
    CredentialTypes,
    IntegrationCredentials,
    IntegrationTypes,
    SoarSubTypes,
)
from tenant.models import DUCortexSOARIncidentFinalModel, DuCortexSOARTenants


@shared_task
def sync_cortex_soar_tenants(
    token: str, ip_address: str, port: int, integration_id: int
):
    """
    Syncs the CortexSOAR tenants with the database.

    This task fetches the accounts from the CortexSOAR instance and
    inserts them into the database.

    :param token: The authentication token to use when logging into the CortexSOAR.
    :param ip_address: The IP address of the CortexSOAR instance.
    :param port: The port to use when connecting to the CortexSOAR instance.
    :param integration_id: The ID of the integration for which to sync the tenants.
    """
    start = time.time()
    try:
        with CortexSOAR(ip_address=ip_address, port=port, token=token) as soar:
            accounts = soar._get_accounts()
            if accounts is None:
                logger.error("No data returned from CortexSOAR accounts endpoint")
                return

            cdc_entries = [
                item
                for item in accounts
                if "name" in item and re.search(r"cdc", item["name"], re.IGNORECASE)
            ]
            accounts = cdc_entries

            transformed_data = soar._transform_accounts(
                accounts=accounts, integration_id=integration_id
            )
            if not isinstance(transformed_data, list):
                logger.error("Invalid data format: Expected a list")
                return

            soar._insert_accounts(transformed_data)

            logger.info(
                f"Successfully synced {len(transformed_data)} CortexSOAR tenants"
            )
            logger.info(
                f"CortexSOAR.sync_itsm_tenants() task took {time.time() - start} seconds"
            )
    except Exception as e:
        logger.error(f"Unexpected error in sync_itsm_tenants: {str(e)}")


@shared_task
def sync_notes_child(token: str, ip_address: str, port: int, integration_id: int):
    start = time.time()
    data = (
        DUCortexSOARIncidentFinalModel.objects.filter(integration_id=integration_id)
        .annotate(note_count=Count("notes"))
        .filter(note_count=0)
        .values("id", "db_id", "account")
    )

    try:
        with CortexSOAR(ip_address=ip_address, port=port, token=token) as soar:
            for item in data:
                incident_id = item["id"]
                db_id = item["db_id"]
                account = "acc_{}".format(item["account"])
                logger.info(
                    f"Syncing notes for incident_id: {incident_id} for account: {account}"
                )
                notes = soar._get_notes(account_name=account, incident_id=db_id)
                if notes is None:
                    logger.error(
                        "No data returned from CortexSOAR sync_notes_child() endpoint"
                    )
                    return

                transformed_data = soar._transform_notes_data(
                    entries=notes,
                    incident_id=incident_id,
                    integration_id=integration_id,
                    account=account,
                )
                soar._insert_notes(records=transformed_data)

                logger.info(
                    f"Successfully synced {len(transformed_data)} CortexSOAR tenants"
                )
                logger.info(
                    f"CortexSOAR.sync_notes_child() task took {time.time() - start} seconds"
                )
    except Exception as e:
        logger.error(f"Unexpected error in sync_notes_child: {str(e)}")


@shared_task
def sync_requests_for_soar():
    # intervals = ["day", "week", "month", "year"]
    intervals = ["year"]
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SOAR_INTEGRATION,
        integration__soar_subtype=SoarSubTypes.CORTEX_SOAR,
        credential_type=CredentialTypes.API_KEY,
    )

    for integration in results:
        cortex_tenants = DuCortexSOARTenants.objects.filter(
            integration=integration.id
        ).all()
        with CortexSOAR(
            ip_address=integration.ip_address,
            port=integration.port,
            token=integration.api_key,
        ) as soar:
            for cortex_tenant in cortex_tenants:
                logger.info(
                    f"Getting the Incident for the CortexSOAR tenant : {cortex_tenant.name}"
                )
                for interval in intervals:
                    logger.info(f"Getting the Incident for the interval : {interval}")
                    data = soar._get_incidents(
                        account_name=cortex_tenant.name, day_week_month=interval
                    )
                    if not data:
                        logger.warning(
                            f"No data returned for the CortexSOAR tenant : {cortex_tenant.name}"
                        )
                        continue
                    if data["data"] is None:
                        logger.warning(
                            f"No data returned for the CortexSOAR tenant : {cortex_tenant.name}"
                        )
                        continue

                    records = soar._transform_incidents(
                        data=data,
                        integration_id=integration.integration,
                        cortex_tenant=cortex_tenant,
                    )
                    logger.info(
                        f"Ingesting the Incident for the CortexSOAR tenant : {cortex_tenant.name}"
                    )
                    soar._insert_incidents(records=records)
                    purge_old_soar_incidents.delay()


@shared_task
def sync_notes_for_incident(
    token: str, ip_address: str, port: int, integration_id: int, incident_id: int
):
    start = time.time()
    # Get the specific incident with no notes
    incident_data = (
        DUCortexSOARIncidentFinalModel.objects.filter(
            id=incident_id, integration_id=integration_id
        )
        .annotate(note_count=Count("notes"))
        .filter(note_count=0)
        .values("id", "db_id", "account")
        .first()
    )

    if not incident_data:
        logger.info(f"Incident {incident_id} already has notes or doesn't exist.")
        return

    try:
        with CortexSOAR(ip_address=ip_address, port=port, token=token) as soar:
            db_id = incident_data["db_id"]
            account = f"acc_{incident_data['account']}"
            logger.info(
                f"Syncing notes for incident_id={incident_id}, account={account}"
            )
            notes = soar._get_notes(account_name=account, incident_id=db_id)

            if not notes:
                logger.warning(f"No notes returned for incident_id={incident_id}")
                return

            transformed_data = soar._transform_notes_data(
                entries=notes,
                incident_id=incident_id,
                integration_id=integration_id,
                account=account,
            )
            soar._insert_notes(records=transformed_data)

            logger.success(
                f"Synced {len(transformed_data)} notes for incident_id={incident_id}"
            )
            logger.info(
                f"sync_notes_for_incident() took {time.time() - start:.2f} seconds"
            )

    except Exception as e:
        logger.error(f"Error syncing notes for incident_id={incident_id}: {str(e)}")


@shared_task
def sync_notes():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SOAR_INTEGRATION,
        integration__soar_subtype=SoarSubTypes.CORTEX_SOAR,
        credential_type=CredentialTypes.API_KEY,
    )

    for result in results:
        sync_notes_child.delay(
            token=result.api_key,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )


@shared_task
def sync_soar_data():
    logger.info("Running sync_soar_data() task")
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SOAR_INTEGRATION,
        integration__soar_subtype=SoarSubTypes.CORTEX_SOAR,
        credential_type=CredentialTypes.API_KEY,
    )

    for result in results:
        sync_cortex_soar_tenants.delay(
            token=result.api_key,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )
    sync_requests_for_soar.delay()
    sync_notes.delay()
    purge_old_soar_incidents.delay()
    logger.info("sync_soar_data() task completed and time updated")


@shared_task
def purge_old_soar_incidents(cutoff_year=2025, dry_run=False):
    """
    Bulk delete DUCortexSOARIncidentFinalModel records where occured (DATE) < Jan 1 of cutoff_year.

    Args:
        cutoff_year: Year threshold (default 2025). Records before Jan 1 of this year will be deleted.
        dry_run: If True, only log what would be deleted without actually deleting.

    Returns:
        dict: Summary of the operation with counts and status.
    """
    DateTimeStorage.store_current_time()
    start_time = time.time()

    # Use DATE-only cutoff (January 1 of the cutoff year)
    cutoff_date = date(cutoff_year, 1, 1)

    logger.info(
        f"[purge_old_soar_incidents] Starting with cutoff DATE: {cutoff_date} (bulk delete)"
    )

    # Query for old incidents based on 'occured' DATE (not datetime)
    old_incidents = DUCortexSOARIncidentFinalModel.objects.filter(
        occured__date__lt=cutoff_date
    )

    total_count = old_incidents.count()

    if total_count == 0:
        logger.info("[purge_old_soar_incidents] No incidents found to purge")
        return {
            "status": "success",
            "message": "No incidents found to purge",
            "total_deleted": 0,
            "dry_run": dry_run,
            "cutoff_date": cutoff_date.isoformat(),
            "execution_time": time.time() - start_time,
        }

    if dry_run:
        # In dry run mode, just log what would be deleted (limit sampling to avoid large logs)
        sample_incidents = list(
            old_incidents.values("id", "db_id", "name", "occured", "account")[:10]
        )
        logger.info(
            f"[purge_old_soar_incidents] DRY RUN: Would delete {total_count} incidents before {cutoff_date}"
        )
        logger.info(
            f"[purge_old_soar_incidents] Sample (first 10) to be deleted: {sample_incidents}"
        )
        return {
            "status": "dry_run",
            "message": f"Would delete {total_count} incidents",
            "total_count": total_count,
            "dry_run": True,
            "cutoff_date": cutoff_date.isoformat(),
            "execution_time": time.time() - start_time,
        }

    # Perform a single bulk delete relying on DB/Django cascade for related notes
    try:
        deleted_count, deleted_details = old_incidents.delete()
        logger.success(
            f"[purge_old_soar_incidents] Bulk deleted {deleted_count} incidents older than {cutoff_date}. "
            f"Task took {time.time() - start_time:.2f} seconds"
        )
        return {
            "status": "success",
            "message": f"Successfully deleted {deleted_count} incidents",
            "total_deleted": deleted_count,
            "details": deleted_details,
            "dry_run": False,
            "cutoff_date": cutoff_date.isoformat(),
            "execution_time": time.time() - start_time,
        }
    except Exception as e:
        logger.error(
            f"[purge_old_soar_incidents] Error during purge operation: {str(e)}"
        )
        return {
            "status": "error",
            "message": str(e),
            "dry_run": False,
            "cutoff_date": cutoff_date.isoformat(),
            "execution_time": time.time() - start_time,
        }
