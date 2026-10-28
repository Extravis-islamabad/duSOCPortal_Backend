import time
from datetime import timedelta

from celery import shared_task
from django.core.cache import cache
from django.db.models import Max, Q
from loguru import logger

from common.constants import FortiSOARConstants
from common.modules.fortisoar import FortiSOAR
from integration.models import (
    CredentialTypes,
    IntegrationCredentials,
    IntegrationTypes,
    SoarSubTypes,
)
from tenant.models import DUFortiSOARIncidentModel, DUFortiSOARTenants


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
            logger.info(f"Successfully synced {len(transformed_data)} tenants")
    except Exception as e:
        logger.error(f"Error sync_forti_soar_tenants: {e}")

    logger.info(
        f"FortiSOARTenants.sync_forti_soar_tenants() task took {time.time() - start} seconds"
    )


@shared_task
def sync_forti_soar_alert_for_tenant(
    forti_soar_tenant_id,
    forti_soar_tenant_name,
    ip_address,
    port,
    api_key,
    integration_id,
):
    logger.info(f"Running sync_forti_soar_alerts for tenant {forti_soar_tenant_name}")
    if forti_soar_tenant_name == "CDC-Mey-Test":
        return

    # A tenant sweep can take longer than the interval it is scheduled on, so
    # without this guard each tick stacks another concurrent full collection of
    # the same tenant on top of the ones still running. cache.add() is atomic,
    # so only the first caller through takes the lock.
    lock_key = f"forti_soar_sync:{integration_id}:{forti_soar_tenant_id}"
    if not cache.add(
        lock_key, "1", timeout=FortiSOARConstants.TENANT_SYNC_LOCK_SECONDS
    ):
        logger.warning(
            f"Skipping sync for tenant {forti_soar_tenant_name}: a previous sweep "
            f"is still running. This run is dropped rather than queued."
        )
        return

    try:
        modified_after = get_tenant_watermark(
            forti_soar_tenant_id=forti_soar_tenant_id,
            integration_id=integration_id,
            tenant_name=forti_soar_tenant_name,
        )
        with FortiSOAR(
            ip_address=ip_address,
            port=port,
            token=api_key,
        ) as fsoar:
            data = fsoar._get_alerts(
                tenant_name=forti_soar_tenant_name,
                modified_after=modified_after,
            )
            if not data:
                logger.info(
                    f"No new or changed alerts for tenant {forti_soar_tenant_name}"
                )
                return
            transformed_data = fsoar.transform_alerts(
                data=data,
                integration_id=integration_id,
                forti_soar_tenant_id=forti_soar_tenant_id,
                name=forti_soar_tenant_name,
            )
            logger.info(
                f"Transformed {len(transformed_data)} alerts for tenant {forti_soar_tenant_name}"
            )
            fsoar._insert_alerts(transformed_data)
            record_tenant_watermark(
                forti_soar_tenant_id=forti_soar_tenant_id,
                tenant_name=forti_soar_tenant_name,
                alerts=data,
                parse=fsoar.parse_modify_date,
            )
    finally:
        cache.delete(lock_key)


def record_tenant_watermark(forti_soar_tenant_id, tenant_name, alerts, parse):
    """
    Store the newest modifyDate seen in this response for the tenant.

    ``parse`` must yield timezone-aware datetimes, not the ISO strings that
    safe_parse_datetime() produces for storage, or the comparison against the
    stored mark raises.

    Taken from what FortiSOAR returned rather than from what was stored, so
    that alerts discarded by transform_alerts() still move the mark forward.
    Only ever moves forward, so a response that happens to arrive out of order
    cannot rewind it and cause alerts to be skipped.
    """
    seen = [parse(alert.get("modifyDate")) for alert in alerts]
    newest = max((value for value in seen if value is not None), default=None)
    if newest is None:
        logger.warning(
            f"No usable modifyDate in the response for tenant {tenant_name}; "
            f"leaving the high-water mark unchanged"
        )
        return

    updated = DUFortiSOARTenants.objects.filter(
        id=forti_soar_tenant_id
    ).filter(
        Q(alerts_synced_until__lt=newest) | Q(alerts_synced_until__isnull=True)
    ).update(alerts_synced_until=newest)

    if updated:
        logger.info(
            f"Tenant {tenant_name} high-water mark advanced to {newest.isoformat()}"
        )


def get_tenant_watermark(forti_soar_tenant_id, integration_id, tenant_name):
    """
    The point in time from which this tenant's alerts should be requested.

    Returns the newest ``modified`` timestamp already stored for the tenant,
    moved back by a short overlap so an alert changed while the previous sweep
    was in flight cannot fall into the gap between two runs. Returns ``None``
    when we hold nothing for the tenant yet, which requests the full history -
    the one case where that is the correct thing to do.
    """
    newest = (
        DUFortiSOARTenants.objects.filter(id=forti_soar_tenant_id)
        .values_list("alerts_synced_until", flat=True)
        .first()
    )

    if newest is None:
        # Nothing recorded yet. Seed from the newest stored alert so the first
        # run after deployment is not a full-history fetch for every tenant at
        # once; it is only ever used until the first successful sync writes the
        # real mark.
        newest = DUFortiSOARIncidentModel.objects.filter(
            forti_soar_tenant_id=forti_soar_tenant_id,
            integration_id=integration_id,
        ).aggregate(newest=Max("modified"))["newest"]

    if newest is None:
        logger.info(
            f"No alerts stored yet for tenant {tenant_name}; requesting full history"
        )
        return None

    watermark = newest - timedelta(
        minutes=FortiSOARConstants.WATERMARK_OVERLAP_MINUTES
    )
    logger.info(
        f"Tenant {tenant_name} high-water mark {newest.isoformat()}, "
        f"requesting from {watermark.isoformat()}"
    )
    return watermark


@shared_task
def sync_forti_soar_alerts():
    logger.info("Running sync_forti_soar_alerts() task")
    time.time()
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SOAR_INTEGRATION,
        integration__soar_subtype=SoarSubTypes.FORTI_SOAR,
        credential_type=CredentialTypes.API_KEY,
    )

    for integration in results:
        forti_soar_tenants = DUFortiSOARTenants.objects.filter(
            integration=integration.id
        ).all()
        for forti_soar_tenant in forti_soar_tenants:
            kwargs = {
                "forti_soar_tenant_id": forti_soar_tenant.id,
                "forti_soar_tenant_name": forti_soar_tenant.name,
                "ip_address": integration.ip_address,
                "port": integration.port,
                "api_key": integration.api_key,
                "integration_id": integration.integration.id,
            }
            sync_forti_soar_alert_for_tenant.delay(**kwargs)


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

    # Called once, after the loop. sync_forti_soar_alerts() already iterates
    # over every credential and every tenant underneath it, so calling it per
    # credential dispatched the whole sweep N times - N^2 * tenants requests to
    # FortiSOAR per run instead of N * tenants. Harmless at one credential,
    # which is what Production has; DEV had eight.
    sync_forti_soar_alerts()
