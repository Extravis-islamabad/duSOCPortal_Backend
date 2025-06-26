import time
from datetime import datetime

from celery import shared_task
from loguru import logger

from common.constants import IBMQradarConstants
from common.modules.ibm_qradar import IBMQradar
from integration.models import (
    CredentialTypes,
    IntegrationCredentials,
    IntegrationTypes,
    SiemSubTypes,
)
from tenant.models import CustomerEPS, DuIbmQradarTenants, IBMQradarEPS


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
def sync_offenses():
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


@shared_task
def sync_event_log_sources_types():
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
            data = ibm_qradar._get_log_sources_types()
            if not data:
                logger.warning(
                    f"No data returned from IBM QRadar Log SOurces types endpoint for integration {result.integration.id}"
                )
            transformed_data = ibm_qradar._transform_log_sources_types(
                log_sources_types=data, integration_id=result.integration.id
            )
            if transformed_data:
                ibm_qradar._insert_log_sources_types(transformed_data)


@shared_task
def sync_eps_for_domain(
    username: str, password: str, ip_address: str, port: int, integration_id: int
):
    db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info("Running QRadarTasks.sync_eps_for_domain() task")
        for domain_id in db_ids:
            logger.info(f"Syncing EPS for domain {domain_id}")
            search_id = ibm_qradar._get_eps_domain(domain_id=domain_id)
            flag = ibm_qradar._check_eps_results_by_search_id(search_id=search_id)
            if not flag:
                logger.warning(
                    f"IBM QRadar EPS sync failed for domain {domain_id} for integration {integration_id}"
                )
                continue
            data = ibm_qradar._get_eps_results_by_search_id(search_id=search_id)
            transformed_data = ibm_qradar._transform_eps_data(
                data_list=data, integration=integration_id
            )
            if transformed_data:
                ibm_qradar._insert_eps(transformed_data)

                logger.info("Completed QRadarTasks.sync_eps_for_domain() task")


@shared_task
def sync_eps_for_domain_for_admin(
    username: str, password: str, ip_address: str, port: int, integration_id: int
):
    db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info("Running QRadarTasks.sync_eps_for_domain_for_admin() task")
        for domain_id in db_ids:
            logger.info(f"Syncing Customer EPS for domain {domain_id}")
            search_id = ibm_qradar._get_do_aql_query(
                query=IBMQradarConstants.AQL_QUERY_FOR_ADMIN_DASHBOARD
            )
            flag = ibm_qradar._check_eps_results_by_search_id(search_id=search_id)
            if not flag:
                logger.warning(
                    f"IBM QRadar Customer EPS sync failed for integration {integration_id}"
                )
                continue
            data = ibm_qradar._get_eps_results_by_search_id(search_id=search_id)
            transformed_data = ibm_qradar._transform_customer_eps_data(
                data_list=data, integration=integration_id
            )
            if transformed_data:
                ibm_qradar._insert_customer_eps(transformed_data)
                logger.success(
                    f"IBM QRadar Customer EPS sync completed for integration {integration_id}"
                )


@shared_task
def sync_total_events_for_domain(
    username: str, password: str, ip_address: str, port: int, integration_id: int
):
    """
    Syncs total event counts for each domain using AQL query and stores in TotalEvents model.

    :param username: QRadar username
    :param password: QRadar password
    :param ip_address: QRadar IP address
    :param port: QRadar port
    :param integration_id: Integration ID
    :param start_date: Query start date (default: '2025-04-01 00:00:00')
    :param stop_date: Query stop date (default: '2025-04-30 23:59:59')
    """
    db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)
    transformed_data = []
    today = datetime.today().date()
    # Combine with time.min and time.max
    min_dt = datetime.combine(today, time.min)  # 00:00:00
    max_dt = datetime.combine(today, time.max)  # 23:59:59.999999

    # Format as "DD-MM-YYYY HH:MM:SS"
    start_date = min_dt.strftime("%d-%m-%Y %H:%M:%S")
    end_date = max_dt.strftime("%d-%m-%Y %H:%M:%S")
    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info("Running QRadarTasks.sync_total_events_for_domain() task")
        for domain_id in db_ids:
            logger.info(f"Syncing Total Events for domain {domain_id}")
            aql_query = f"""
                SELECT SUM(eventcount) AS total_events
                FROM events
                WHERE domainid = {domain_id}
                START PARSEDATETIME('{start_date}')
                STOP PARSEDATETIME('{end_date}')
            """  # nosec
            search_id = ibm_qradar._get_do_aql_query(query=aql_query)
            flag = ibm_qradar._check_eps_results_by_search_id(search_id=search_id)
            if not flag:
                logger.warning(
                    f"IBM QRadar Total Events sync failed for domain {domain_id}, integration {integration_id}"
                )
                continue
            data = ibm_qradar._get_eps_results_by_search_id(search_id=search_id)
            transformed = ibm_qradar._transform_total_events_data(
                data=data, integration=integration_id, domain_id=domain_id
            )
            if transformed:
                transformed_data.append(transformed)
                logger.info(
                    f"IBM QRadar Total Events data transformed for domain {domain_id}"
                )

        if transformed_data:
            ibm_qradar._insert_total_events(transformed_data)
            logger.info(
                f"IBM QRadar Total Events sync completed for integration {integration_id}"
            )


@shared_task
def sync_ibm_qradar_data():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_qradar_tenants.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )
        sync_event_collectors.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )
        sync_event_log_assets.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )
        sync_event_log_sources_types.delay()
        sync_offenses.delay()
        IBMQradarEPS.objects.all().delete()
        sync_eps_for_domain.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )


@shared_task
def sync_ibm():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )
    IBMQradarEPS.objects.all().delete()
    for result in results:
        sync_eps_for_domain(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )
        sync_total_events_for_domain(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )


@shared_task
def sync_ibm_admin_eps():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )
    CustomerEPS.objects.all().delete()
    for result in results:
        sync_eps_for_domain_for_admin(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )
