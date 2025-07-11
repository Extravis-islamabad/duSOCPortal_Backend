import time
from datetime import timedelta

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
from tenant.models import (
    CorrelatedEventLog,
    CustomerEPS,
    DuIbmQradarTenants,
    WeeklyCorrelatedEventLog,
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
def sync_ibm_tenant_eps():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )
    for result in results:
        sync_eps_for_domain.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )


@shared_task
def sync_eps_for_domain_for_admin(
    username: str, password: str, ip_address: str, port: int, integration_id: int
):
    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info("Running QRadarTasks.sync_eps_for_domain_for_admin() task")
        logger.info("Syncing Customer EPS for admin dashboard")
        search_id = ibm_qradar._get_do_aql_query(
            query=IBMQradarConstants.AQL_QUERY_FOR_ADMIN_DASHBOARD
        )
        flag = ibm_qradar._check_eps_results_by_search_id(search_id=search_id)
        if not flag:
            logger.warning(
                f"IBM QRadar Customer EPS sync failed for integration {integration_id}"
            )
            return
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
    from datetime import datetime, time

    # Get today's date
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
    for result in results:
        # sync_eps_for_domain(
        #     username=result.username,
        #     password=result.password,
        #     ip_address=result.ip_address,
        #     port=result.port,
        #     integration_id=result.integration.id,
        # )
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


@shared_task
def sync_event_count_for_admin(username, password, ip_address, port, integration_id):
    from datetime import datetime, time  # Import inside function

    db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

    # Get today's date with min and max time
    today = datetime.today().date()
    min_dt = datetime.combine(today, time.min)  # 00:00:00
    max_dt = datetime.combine(today, time.max)  # 23:59:59.999999

    # Format as "YYYY-MM-DD HH:MM:SS" for QRadar AQL
    start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info("Running QRadarTasks.sync_event_count_for_admin() task")

        for domain_id in db_ids:
            query = IBMQradarConstants.AQL_QUERY_FOR_SUSPICIOUS_EVENTS.format(
                domain_id=domain_id, start_time=start_str, end_time=end_str
            )
            logger.info(
                f"Executing AQL for domain {domain_id} (From {start_str} To {end_str})"
            )

            search_id = ibm_qradar._get_do_aql_query(query=query)
            data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)

            if not data_ready:
                logger.warning(f"No data returned for domain {domain_id}")
                continue

            results = ibm_qradar._get_eps_results_by_search_id(search_id)
            transformed = ibm_qradar._transform_event_count_data(
                results, integration_id, domain_id
            )
            if transformed:
                ibm_qradar._insert_event_count_data(transformed)


# @shared_task
# def sync_recon_for_admin(username, password, ip_address, port, integration_id):
#     from datetime import datetime, time  # Import inside function

#     db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

#     # Get today's date range
#     today = datetime.today().date()
#     min_dt = datetime.combine(today, time.min)  # 00:00:00
#     max_dt = datetime.combine(today, time.max)  # 23:59:59.999999

#     # Format for QRadar AQL
#     start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
#     end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

#     with IBMQradar(
#         username=username, password=password, ip_address=ip_address, port=port
#     ) as ibm_qradar:
#         logger.info("Running QRadarTasks.sync_recon_for_admin() task")

#         for domain_id in db_ids:
#             query = IBMQradarConstants.AQL_QUERY_FOR_RECON_EVENTS.format(
#                 domain_id=domain_id,
#                 start_time=start_str,
#                 end_time=end_str,
#             )
#             logger.info(
#                 f"Executing RECON AQL for domain {domain_id} ({start_str} → {end_str})"
#             )

#             search_id = ibm_qradar._get_do_aql_query(query=query)
#             data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)

#             if not data_ready:
#                 logger.warning(f"No recon data returned for domain {domain_id}")
#                 continue

#             results = ibm_qradar._get_eps_results_by_search_id(search_id)
#             transformed = ibm_qradar._transform_recon_data(
#                 results, integration_id, domain_id
#             )

#             if transformed:
#                 ibm_qradar._insert_recon_event_data(transformed)
@shared_task
def sync_recon_for_admin(username, password, ip_address, port, integration_id):
    from datetime import datetime, time  # Import inside function

    db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

    today = datetime.today().date() - timedelta(days=7)
    # Get today's date range
    # TODO : Commenting this
    # today = datetime.today().date()

    min_dt = datetime.combine(today, time.min)  # 00:00:00
    max_dt = datetime.combine(today, time.max)  # 23:59:59.999999

    start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info("Running QRadarTasks.sync_recon_for_admin() task")

        for domain_id in db_ids:
            query = IBMQradarConstants.AQL_QUERY_FOR_RECON_EVENTS.format(
                domain_id=domain_id,
                start_time=start_str,
                end_time=end_str,
            )

            logger.info(
                f"Executing RECON AQL for domain {domain_id} ({start_str} → {end_str})"
            )

            search_id = ibm_qradar._get_do_aql_query(query=query)
            data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)

            if not data_ready:
                logger.warning(f"No recon data returned for domain {domain_id}")
                continue

            results = ibm_qradar._get_eps_results_by_search_id(search_id)
            transformed = ibm_qradar._transform_recon_data(
                results, integration_id, domain_id, date=start_str
            )

            if transformed:
                ibm_qradar._insert_recon_event_data(transformed)


@shared_task
def sync_ibm_event_counts():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_event_count_for_admin.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )


@shared_task
def sync_recon_event_counts():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_recon_for_admin.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )


@shared_task
def sync_correlated_event_counts():
    """Sync correlated event counts for all IBM QRadar integrations"""
    try:
        logger.info("Starting sync_correlated_event_counts task")

        results = IntegrationCredentials.objects.filter(
            integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
            integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
            credential_type=CredentialTypes.USERNAME_PASSWORD,
        )

        logger.info(f"Found {results.count()} QRadar integrations")

        # Clear existing correlated event logs
        deleted_count = CorrelatedEventLog.objects.all().delete()[0]
        logger.info(f"Deleted {deleted_count} existing CorrelatedEventLog records")

        for result in results:
            logger.info(f"Triggering sync for integration {result.integration.id}")
            sync_correlated_for_admin.delay(
                username=result.username,
                password=result.password,
                ip_address=result.ip_address,
                port=result.port,
                integration_id=result.integration.id,
            )

        logger.info("Successfully triggered all correlated event sync tasks")

    except Exception as e:
        logger.error(f"Error in sync_correlated_event_counts: {str(e)}", exc_info=True)
        raise


@shared_task
def sync_correlated_for_admin(username, password, ip_address, port, integration_id):
    """Sync correlated events for a specific admin/integration"""
    from datetime import datetime, time  # Import inside function

    try:
        logger.info(
            f"Starting sync_correlated_for_admin for integration {integration_id}"
        )

        db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)
        db_ids_list = list(db_ids)
        logger.info(f"Processing {len(db_ids_list)} QRadar tenants: {db_ids_list}")

        if not db_ids_list:
            logger.warning("No QRadar tenants found")
            return

        # Get today's date range
        today = datetime.today().date()
        min_dt = datetime.combine(today, time.min)  # 00:00:00
        max_dt = datetime.combine(today, time.max)  # 23:59:59.999999

        start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
        end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

        logger.info(f"Date range: {start_str} to {end_str}")

        with IBMQradar(
            username=username, password=password, ip_address=ip_address, port=port
        ) as ibm_qradar:
            logger.info("Successfully connected to IBM QRadar")
            logger.info("Running QRadarTasks.sync_correlated_for_admin() task")

            total_processed = 0
            total_inserted = 0

            for domain_id in db_ids_list:
                try:
                    logger.info(f"Processing domain {domain_id}")

                    query = IBMQradarConstants.AQL_QUERY_FOR_CORRELATED_EVENTS.format(
                        domain_id=domain_id,
                        start_time=start_str,
                        end_time=end_str,
                    )
                    logger.info(f"Executing CORRELATED AQL for domain {domain_id}")
                    logger.debug(f"AQL Query: {query}")

                    # Execute the query
                    search_id = ibm_qradar._get_do_aql_query(query=query)
                    logger.info(f"Search ID: {search_id}")

                    if not search_id:
                        logger.error(f"Failed to get search ID for domain {domain_id}")
                        continue

                    # Check if results are ready
                    data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)
                    logger.info(f"Data ready status: {data_ready}")

                    if not data_ready:
                        logger.warning(
                            f"No correlated data returned for domain {domain_id}"
                        )
                        continue

                    # Get the results
                    results = ibm_qradar._get_eps_results_by_search_id(search_id)
                    logger.info(
                        f"Raw results from QRadar for domain {domain_id}: {results}"
                    )

                    if not results:
                        logger.warning(f"Empty results for domain {domain_id}")
                        continue

                    # Transform the data
                    transformed = ibm_qradar._transform_correlated_data(
                        results, integration_id, domain_id
                    )
                    logger.info(
                        f"Transformed data for domain {domain_id}: {transformed}"
                    )

                    if transformed:
                        success = ibm_qradar._insert_correlated_event_data(transformed)
                        if success:
                            total_inserted += len(transformed)
                            logger.info(f"Successfully processed domain {domain_id}")
                        else:
                            logger.error(
                                f"Failed to insert data for domain {domain_id}"
                            )
                    else:
                        logger.warning(f"No transformed data for domain {domain_id}")

                    total_processed += 1

                except Exception as e:
                    logger.error(
                        f"Error processing domain {domain_id}: {str(e)}", exc_info=True
                    )
                    continue

            logger.info(
                f"Completed sync_correlated_for_admin: {total_processed} domains processed, {total_inserted} records inserted"
            )

    except Exception as e:
        logger.error(f"Error in sync_correlated_for_admin: {str(e)}", exc_info=True)
        raise


@shared_task
def sync_weekly_correlated_event_counts():
    """Sync weekly correlated event counts for all IBM QRadar integrations"""
    try:
        logger.info("Starting sync_weekly_correlated_event_counts task")

        results = IntegrationCredentials.objects.filter(
            integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
            integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
            credential_type=CredentialTypes.USERNAME_PASSWORD,
        )

        logger.info(f"Found {results.count()} QRadar integrations")

        # Clear existing weekly correlated event logs
        deleted_count = WeeklyCorrelatedEventLog.objects.all().delete()[0]
        logger.info(
            f"Deleted {deleted_count} existing WeeklyCorrelatedEventLog records"
        )

        for result in results:
            logger.info(
                f"Triggering weekly sync for integration {result.integration.id}"
            )
            sync_weekly_correlated_for_admin.delay(
                username=result.username,
                password=result.password,
                ip_address=result.ip_address,
                port=result.port,
                integration_id=result.integration.id,
            )

        logger.info("Successfully triggered all weekly correlated event sync tasks")

    except Exception as e:
        logger.error(
            f"Error in sync_weekly_correlated_event_counts: {str(e)}", exc_info=True
        )
        raise


# TODO : Talha look onto this
@shared_task
def sync_weekly_correlated_for_admin(
    username, password, ip_address, port, integration_id
):
    """Sync weekly correlated events for a specific admin/integration"""
    from datetime import datetime, timedelta  # Import inside function

    try:
        logger.info(
            f"Starting sync_weekly_correlated_for_admin for integration {integration_id}"
        )

        db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)
        db_ids_list = list(db_ids)
        logger.info(f"Processing {len(db_ids_list)} QRadar tenants: {db_ids_list}")

        if not db_ids_list:
            logger.warning("No QRadar tenants found")
            return

        # Set date range (last 4 weeks from current date)
        now = datetime.now()
        end_time = now.replace(hour=23, minute=59, second=59, microsecond=0)
        start_time = (now - timedelta(weeks=4)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )

        start_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
        end_str = end_time.strftime("%Y-%m-%d %H:%M:%S")

        logger.info(f"Date range: {start_str} to {end_str}")

        with IBMQradar(
            username=username, password=password, ip_address=ip_address, port=port
        ) as ibm_qradar:
            logger.info("Successfully connected to IBM QRadar")
            logger.info("Running QRadarTasks.sync_weekly_correlated_for_admin() task")

            total_processed = 0
            total_inserted = 0

            for domain_id in db_ids_list:
                try:
                    logger.info(f"Processing weekly data for domain {domain_id}")

                    query = IBMQradarConstants.AQL_QUERY_FOR_WEEKLY_CORRELATED_EVENTS.format(
                        domain_id=domain_id,
                        start_time=start_str,
                        end_time=end_str,
                    )
                    logger.info(
                        f"Executing WEEKLY CORRELATED AQL for domain {domain_id}"
                    )
                    logger.debug(f"AQL Query: {query}")

                    # Execute the query
                    search_id = ibm_qradar._get_do_aql_query(query=query)
                    logger.info(f"Search ID: {search_id}")

                    if not search_id:
                        logger.error(f"Failed to get search ID for domain {domain_id}")
                        continue

                    # Check if results are ready
                    data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)
                    logger.info(f"Data ready status: {data_ready}")

                    if not data_ready:
                        logger.warning(
                            f"No weekly correlated data returned for domain {domain_id}"
                        )
                        continue

                    # Get the results
                    results = ibm_qradar._get_eps_results_by_search_id(search_id)
                    logger.info(
                        f"Raw weekly results from QRadar for domain {domain_id}: {results}"
                    )

                    if not results:
                        logger.warning(f"Empty weekly results for domain {domain_id}")
                        continue

                    # Transform the data
                    transformed = ibm_qradar._transform_weekly_correlated_data(
                        results, integration_id, domain_id
                    )
                    logger.info(
                        f"Transformed weekly data for domain {domain_id}: {transformed}"
                    )

                    if transformed:
                        success = ibm_qradar._insert_weekly_correlated_event_data(
                            transformed
                        )
                        if success:
                            total_inserted += len(transformed)
                            logger.info(
                                f"Successfully processed weekly data for domain {domain_id}"
                            )
                        else:
                            logger.error(
                                f"Failed to insert weekly data for domain {domain_id}"
                            )
                    else:
                        logger.warning(
                            f"No transformed weekly data for domain {domain_id}"
                        )

                    total_processed += 1

                except Exception as e:
                    logger.error(
                        f"Error processing weekly data for domain {domain_id}: {str(e)}",
                        exc_info=True,
                    )
                    continue

            logger.info(
                f"Completed sync_weekly_correlated_for_admin: {total_processed} domains processed, {total_inserted} records inserted"
            )

    except Exception as e:
        logger.error(
            f"Error in sync_weekly_correlated_for_admin: {str(e)}", exc_info=True
        )
        raise


@shared_task
def sync_suspicious_event_counts():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_suspicious_for_admin.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )

@shared_task
def sync_suspicious_for_admin(username, password, ip_address, port, integration_id):
    from datetime import datetime, time  # Import inside function

    db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

    today = datetime.today().date() - timedelta(days=7)
    # Get today's date range
    # TODO : Commenting this
    # today = datetime.today().date()

    min_dt = datetime.combine(today, time.min)  # 00:00:00
    max_dt = datetime.combine(today, time.max)  # 23:59:59.999999

    start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info("Running QRadarTasks.sync_suspicious_for_admin() task")

        for domain_id in db_ids:
            query = IBMQradarConstants.AQL_QUERY_FOR_SUSPICIOUS_EVENTS.format(
                domain_id=domain_id,
                start_time=start_str,
                end_time=end_str,
            )

            logger.info(
                f"Executing SUSPICIOUS AQL for domain {domain_id} ({start_str} → {end_str})"
            )

            search_id = ibm_qradar._get_do_aql_query(query=query)
            data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)

            if not data_ready:
                logger.warning(f"No suspicious data returned for domain {domain_id}")
                continue

            results = ibm_qradar._get_eps_results_by_search_id(search_id)
            transformed = ibm_qradar._transform_suspicious_data(
                results, integration_id, domain_id, date=start_str
            )

            if transformed:
                ibm_qradar._insert_suspicious_event_data(transformed)


@shared_task
def sync_dos_event_counts():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_dos_for_admin.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )


@shared_task
def sync_dos_for_admin(username, password, ip_address, port, integration_id):
    from datetime import datetime, time  # Import inside function

    db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

    today = datetime.today().date() - timedelta(days=8)
    # Get today's date range
    # TODO : Commenting this
    # today = datetime.today().date()

    min_dt = datetime.combine(today, time.min)  # 00:00:00
    max_dt = datetime.combine(today, time.max)  # 23:59:59.999999

    start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info("Running QRadarTasks.sync_dos_for_admin() task")

        for domain_id in db_ids:
            query = IBMQradarConstants.AQL_QUERY_FOR_DOS_EVENTS.format(
                domain_id=domain_id,
                start_time=start_str,
                end_time=end_str,
            )

            logger.info(
                f"Executing DOS AQL for domain {domain_id} ({start_str} → {end_str})"
            )

            search_id = ibm_qradar._get_do_aql_query(query=query)
            data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)

            if not data_ready:
                logger.warning(f"No DoS data returned for domain {domain_id}")
                continue

            results = ibm_qradar._get_eps_results_by_search_id(search_id)
            transformed = ibm_qradar._transform_dos_data(
                results, integration_id, domain_id, date=start_str
            )

            if transformed:
                ibm_qradar._insert_dos_event_data(transformed)


@shared_task
def sync_top_dos_event_counts():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_top_dos_for_admin.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )




@shared_task
def sync_top_dos_for_admin(username, password, ip_address, port, integration_id):
    from datetime import datetime, time  # Import inside function

    db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

    today = datetime.today().date() - timedelta(days=7)
    # Get today's date range
    # TODO : Commenting this
    # today = datetime.today().date()

    min_dt = datetime.combine(today, time.min)  # 00:00:00
    max_dt = datetime.combine(today, time.max)  # 23:59:59.999999

    start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info("Running QRadarTasks.sync_top_dos_for_admin() task")

        for domain_id in db_ids:
            query = IBMQradarConstants.AQL_QUERY_FOR_TOP_DOS_EVENTS.format(
                domain_id=domain_id,
                start_time=start_str,
                end_time=end_str,
            )

            logger.info(
                f"Executing TOP DOS AQL for domain {domain_id} ({start_str} → {end_str})"
            )

            search_id = ibm_qradar._get_do_aql_query(query=query)
            data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)

            if not data_ready:
                logger.warning(f"No top DoS data returned for domain {domain_id}")
                continue

            results = ibm_qradar._get_eps_results_by_search_id(search_id)
            transformed = ibm_qradar._transform_top_dos_data(
                results, integration_id, domain_id, date=start_str
            )

            if transformed:
                ibm_qradar._insert_top_dos_event_data(transformed)
                
@shared_task
def sync_daily_event_counts():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_daily_for_admin.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )

@shared_task
def sync_daily_for_admin(username, password, ip_address, port, integration_id):
    from datetime import datetime, time  # Import inside function

    db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

    today = datetime.today().date() - timedelta(days=7)
    # Get today's date range
    # TODO : Commenting this
    # today = datetime.today().date()

    min_dt = datetime.combine(today, time.min)  # 00:00:00
    max_dt = datetime.combine(today, time.max)  # 23:59:59.999999

    start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info("Running QRadarTasks.sync_daily_for_admin() task")

        for domain_id in db_ids:
            query = IBMQradarConstants.AQL_QUERY_FOR_DAILY_EVENTS.format(
                domain_id=domain_id,
                start_time=start_str,
                end_time=end_str,
            )

            logger.info(
                f"Executing DAILY AQL for domain {domain_id} ({start_str} → {end_str})"
            )

            search_id = ibm_qradar._get_do_aql_query(query=query)
            data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)

            if not data_ready:
                logger.warning(f"No daily event data returned for domain {domain_id}")
                continue

            results = ibm_qradar._get_eps_results_by_search_id(search_id)
            transformed = ibm_qradar._transform_daily_event_data(
                results, integration_id, domain_id, date=start_str
            )

            if transformed:
                ibm_qradar._insert_daily_event_data(transformed)


@shared_task
def sync_top_alert_event_counts():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_top_alert_for_admin.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )


@shared_task
def sync_top_alert_for_admin(username, password, ip_address, port, integration_id):
    from datetime import datetime, time, timedelta  # Import inside function

    db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

    today = datetime.today().date() - timedelta(days=7)
    # Get today's date range
    # TODO: Commenting this
    # today = datetime.today().date()

    min_dt = datetime.combine(today, time.min)  # 00:00:00
    max_dt = datetime.combine(today, time.max)  # 23:59:59.999999

    start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info("Running QRadarTasks.sync_top_alert_for_admin() task")

        for domain_id in db_ids:
            query = IBMQradarConstants.AQL_QUERY_FOR_TOP_ALERT_EVENTS.format(
                domain_id=domain_id,
                start_time=start_str,
                end_time=end_str,
            )

            logger.info(
                f"Executing TOP ALERT AQL for domain {domain_id} ({start_str} → {end_str})"
            )

            search_id = ibm_qradar._get_do_aql_query(query=query)
            data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)

            if not data_ready:
                logger.warning(f"No top alert data returned for domain {domain_id}")
                continue

            results = ibm_qradar._get_eps_results_by_search_id(search_id)
            transformed = ibm_qradar._transform_top_alert_data(
                results, integration_id, domain_id, date=start_str
            )

            if transformed:
                ibm_qradar._insert_top_alert_event_data(transformed)



@shared_task
def sync_daily_closure_reason_counts():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_daily_closure_reason_for_admin.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )

@shared_task
def sync_daily_closure_reason_for_admin(
    username, password, ip_address, port, integration_id
):
    from datetime import datetime, time, timedelta  # Import inside function

    db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

    today = datetime.today().date() - timedelta(days=7)
    # Get today's date range
    # TODO: Commenting this
    # today = datetime.today().date()

    min_dt = datetime.combine(today, time.min)  # 00:00:00
    max_dt = datetime.combine(today, time.max)  # 23:59:59.999999

    start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info("Running QRadarTasks.sync_daily_closure_reason_for_admin() task")

        for domain_id in db_ids:
            query = IBMQradarConstants.AQL_QUERY_FOR_DAILY_CLOSURE_REASONS.format(
                domain_id=domain_id,
                start_time=start_str,
                end_time=end_str,
            )

            logger.info(
                f"Executing DAILY CLOSURE REASON AQL for domain {domain_id} ({start_str} → {end_str})"
            )

            search_id = ibm_qradar._get_do_aql_query(query=query)
            data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)

            if not data_ready:
                logger.warning(
                    f"No daily closure reason data returned for domain {domain_id}"
                )
                continue

            results = ibm_qradar._get_eps_results_by_search_id(search_id)
            transformed = ibm_qradar._transform_daily_closure_reason_data(
                results, integration_id, domain_id, date=start_str
            )

            if transformed:
                ibm_qradar._insert_daily_closure_reason_data(transformed)



@shared_task
def sync_monthly_avg_eps():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_monthly_avg_eps_for_admin.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )



@shared_task
def sync_monthly_avg_eps_for_admin(
    username, password, ip_address, port, integration_id
):
    from datetime import datetime, time, timedelta  # Import inside function

    db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

    today = datetime.today().date() - timedelta(days=7)
    # Get today's date range
    # TODO: Commenting this
    # today = datetime.today().date()

    min_dt = datetime.combine(today, time.min)  # 00:00:00
    max_dt = datetime.combine(today, time.max)  # 23:59:59.999999

    start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info("Running QRadarTasks.sync_monthly_avg_eps_for_admin() task")

        for domain_id in db_ids:
            query = IBMQradarConstants.AQL_QUERY_FOR_MONTHLY_AVG_EPS.format(
                domain_id=domain_id,
                start_time=start_str,
                end_time=end_str,
            )

            logger.info(
                f"Executing MONTHLY AVG EPS AQL for domain {domain_id} ({start_str} → {end_str})"
            )

            search_id = ibm_qradar._get_do_aql_query(query=query)
            data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)

            if not data_ready:
                logger.warning(
                    f"No monthly avg EPS data returned for domain {domain_id}"
                )
                continue

            results = ibm_qradar._get_eps_results_by_search_id(search_id)
            transformed = ibm_qradar._transform_monthly_avg_eps_data(
                results, integration_id, domain_id, date=start_str
            )

            if transformed:
                ibm_qradar._insert_monthly_avg_eps_data(transformed)


@shared_task
def sync_last_month_avg_eps():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_last_month_avg_eps_for_admin.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )


@shared_task
def sync_last_month_avg_eps_for_admin(
    username, password, ip_address, port, integration_id
):
    from datetime import datetime, time, timedelta  # Import inside function

    db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

    today = datetime.today().date() - timedelta(days=7)
    # Get today's date range
    # TODO: Commenting this
    # today = datetime.today().date()

    min_dt = datetime.combine(today, time.min)  # 00:00:00
    max_dt = datetime.combine(today, time.max)  # 23:59:59.999999

    start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info("Running QRadarTasks.sync_last_month_avg_eps_for_admin() task")

        for domain_id in db_ids:
            query = IBMQradarConstants.AQL_QUERY_FOR_LAST_MONTH_AVG_EPS.format(
                domain_id=domain_id,
                start_time=start_str,
                end_time=end_str,
            )

            logger.info(
                f"Executing LAST MONTH AVG EPS AQL for domain {domain_id} ({start_str} → {end_str})"
            )

            search_id = ibm_qradar._get_do_aql_query(query=query)
            data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)

            if not data_ready:
                logger.warning(
                    f"No last month avg EPS data returned for domain {domain_id}"
                )
                continue

            results = ibm_qradar._get_eps_results_by_search_id(search_id)
            transformed = ibm_qradar._transform_last_month_avg_eps_data(
                results, integration_id, domain_id, date=start_str
            )

            if transformed:
                ibm_qradar._insert_last_month_avg_eps_data(transformed)


@shared_task
def sync_weekly_avg_eps():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_weekly_avg_eps_for_admin.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )




@shared_task
def sync_weekly_avg_eps_for_admin(username, password, ip_address, port, integration_id):
    from datetime import datetime, time, timedelta  # Import inside function

    db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

    today = datetime.today().date() - timedelta(days=7)
    # Get today's date range
    # TODO: Commenting this
    # today = datetime.today().date()

    min_dt = datetime.combine(today, time.min)  # 00:00:00
    max_dt = datetime.combine(today, time.max)  # 23:59:59.999999

    start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info("Running QRadarTasks.sync_weekly_avg_eps_for_admin() task")

        for domain_id in db_ids:
            query = IBMQradarConstants.AQL_QUERY_FOR_WEEKLY_AVG_EPS.format(
                domain_id=domain_id,
                start_time=start_str,
                end_time=end_str,
            )

            logger.info(
                f"Executing WEEKLY AVG EPS AQL for domain {domain_id} ({start_str} → {end_str})"
            )

            search_id = ibm_qradar._get_do_aql_query(query=query)
            data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)

            if not data_ready:
                logger.warning(
                    f"No weekly avg EPS data returned for domain {domain_id}"
                )
                continue

            results = ibm_qradar._get_eps_results_by_search_id(search_id)
            transformed = ibm_qradar._transform_weekly_avg_eps_data(
                results, integration_id, domain_id, date=start_str
            )

            if transformed:
                ibm_qradar._insert_weekly_avg_eps_data(transformed)

@shared_task
def sync_total_traffic():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_total_traffic_for_admin.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )



@shared_task
def sync_total_traffic_for_admin(username, password, ip_address, port, integration_id):
    from datetime import datetime, time, timedelta  # Import inside function

    db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

    today = datetime.today().date() - timedelta(days=8)
    # Get today's date range
    # TODO: Commenting this
    # today = datetime.today().date()

    min_dt = datetime.combine(today, time.min)  # 00:00:00
    max_dt = datetime.combine(today, time.max)  # 23:59:59.999999

    start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info("Running QRadarTasks.sync_total_traffic_for_admin() task")

        for domain_id in db_ids:
            query = IBMQradarConstants.AQL_QUERY_FOR_TOTAL_TRAFFIC.format(
                domain_id=domain_id,
                start_time=start_str,
                end_time=end_str,
            )

            logger.info(
                f"Executing TOTAL TRAFFIC AQL for domain {domain_id} ({start_str} → {end_str})"
            )

            search_id = ibm_qradar._get_do_aql_query(query=query)
            data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)

            if not data_ready:
                logger.warning(f"No total traffic data returned for domain {domain_id}")
                continue

            results = ibm_qradar._get_eps_results_by_search_id(search_id)
            transformed = ibm_qradar._transform_total_traffic_data(
                results, integration_id, domain_id, date=start_str
            )

            if transformed:
                ibm_qradar._insert_total_traffic_data(transformed)

@shared_task
def sync_destination_address_counts():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_destination_address_for_admin.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )


@shared_task
def sync_destination_address_for_admin(
    username, password, ip_address, port, integration_id
):
    from datetime import datetime, time, timedelta  # Import inside function

    db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

    today = datetime.today().date() - timedelta(days=8)
    # Get today's date range
    # TODO: Commenting this
    # today = datetime.today().date()

    min_dt = datetime.combine(today, time.min)  # 00:00:00
    max_dt = datetime.combine(today, time.max)  # 23:59:59.999999

    start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info("Running QRadarTasks.sync_destination_address_for_admin() task")

        for domain_id in db_ids:
            query = IBMQradarConstants.AQL_QUERY_FOR_DESTINATION_ADDRESS_COUNTS.format(
                domain_id=domain_id,
                start_time=start_str,
                end_time=end_str,
            )

            logger.info(
                f"Executing DESTINATION ADDRESS AQL for domain {domain_id} ({start_str} → {end_str})"
            )

            search_id = ibm_qradar._get_do_aql_query(query=query)
            data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)

            if not data_ready:
                logger.warning(
                    f"No destination address data returned for domain {domain_id}"
                )
                continue

            results = ibm_qradar._get_eps_results_by_search_id(search_id)
            transformed = ibm_qradar._transform_destination_address_data(
                results, integration_id, domain_id, date=start_str
            )

            if transformed:
                ibm_qradar._insert_destination_address_data(transformed)


@shared_task
def sync_top_destination_connection_counts():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_top_destination_connection_for_admin.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )



# @shared_task
# def sync_top_destination_connection_for_admin(
#     username, password, ip_address, port, integration_id
# ):
#     from datetime import datetime, time  # Import inside function

#     db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

#     # Get today's date range
#     today = datetime.today().date()
#     min_dt = datetime.combine(today, time.min)  # 00:00:00
#     max_dt = datetime.combine(today, time.max)  # 23:59:59.999999

#     start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
#     end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

#     with IBMQradar(
#         username=username, password=password, ip_address=ip_address, port=port
#     ) as ibm_qradar:
#         logger.info(
#             "Running QRadarTasks.sync_top_destination_connection_for_admin() task"
#         )

#         for domain_id in db_ids:
#             query = IBMQradarConstants.AQL_QUERY_FOR_TOP_DESTINATION_CONNECTION_COUNTS.format(
#                 domain_id=domain_id,
#                 start_time=start_str,
#                 end_time=end_str,
#             )

#             logger.info(
#                 f"Executing TOP DESTINATION CONNECTION AQL for domain {domain_id} ({start_str} → {end_str})"
#             )

#             search_id = ibm_qradar._get_do_aql_query(query=query)
#             data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)

#             if not data_ready:
#                 logger.warning(
#                     f"No top destination connection data returned for domain {domain_id}"
#                 )
#                 continue

#             results = ibm_qradar._get_eps_results_by_search_id(search_id)
#             transformed = ibm_qradar._transform_top_destination_connection_data(
#                 results, integration_id, domain_id
#             )

#             if transformed:
#                 ibm_qradar._insert_top_destination_connection_data(transformed)
@shared_task
def sync_top_destination_connection_for_admin(
    username, password, ip_address, port, integration_id
):
    from datetime import datetime, time, timedelta  # Import inside function

    db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

    today = datetime.today().date() - timedelta(days=8)
    # Get today's date range
    # TODO: Commenting this
    # today = datetime.today().date()

    min_dt = datetime.combine(today, time.min)  # 00:00:00
    max_dt = datetime.combine(today, time.max)  # 23:59:59.999999

    start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info(
            "Running QRadarTasks.sync_top_destination_connection_for_admin() task"
        )

        for domain_id in db_ids:
            query = IBMQradarConstants.AQL_QUERY_FOR_TOP_DESTINATION_CONNECTION_COUNTS.format(
                domain_id=domain_id,
                start_time=start_str,
                end_time=end_str,
            )

            logger.info(
                f"Executing TOP DESTINATION CONNECTION AQL for domain {domain_id} ({start_str} → {end_str})"
            )

            search_id = ibm_qradar._get_do_aql_query(query=query)
            data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)

            if not data_ready:
                logger.warning(
                    f"No top destination connection data returned for domain {domain_id}"
                )
                continue

            results = ibm_qradar._get_eps_results_by_search_id(search_id)
            transformed = ibm_qradar._transform_top_destination_connection_data(
                results, integration_id, domain_id, date=start_str
            )

            if transformed:
                ibm_qradar._insert_top_destination_connection_data(transformed)


@shared_task
def sync_daily_event_counts_logs():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_daily_event_counts_for_admin.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )


# @shared_task
# def sync_daily_event_counts_for_admin(
#     username, password, ip_address, port, integration_id
# ):
#     from datetime import datetime, time  # Import inside function

#     db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

#     # Get today's date range
#     today = datetime.today().date()
#     min_dt = datetime.combine(today, time.min)  # 00:00:00
#     max_dt = datetime.combine(today, time.max)  # 23:59:59.999999

#     start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
#     end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

#     with IBMQradar(
#         username=username, password=password, ip_address=ip_address, port=port
#     ) as ibm_qradar:
#         logger.info("Running QRadarTasks.sync_daily_event_counts_for_admin() task")

#         for domain_id in db_ids:
#             query = IBMQradarConstants.AQL_QUERY_FOR_DAILY_EVENT_COUNTS.format(
#                 domain_id=domain_id,
#                 start_time=start_str,
#                 end_time=end_str,
#             )

#             logger.info(
#                 f"Executing DAILY EVENT COUNTS AQL for domain {domain_id} ({start_str} → {end_str})"
#             )

#             search_id = ibm_qradar._get_do_aql_query(query=query)
#             data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)

#             if not data_ready:
#                 logger.warning(
#                     f"No daily event count data returned for domain {domain_id}"
#                 )
#                 continue

#             results = ibm_qradar._get_eps_results_by_search_id(search_id)
#             transformed = ibm_qradar._transform_daily_event_count_data(
#                 results, integration_id, domain_id
#             )

#             if transformed:
#                 ibm_qradar._insert_daily_event_count_data(transformed)

@shared_task
def sync_daily_event_counts_for_admin(
    username, password, ip_address, port, integration_id
):
    from datetime import datetime, time, timedelta  # Import inside function

    db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

    today = datetime.today().date() - timedelta(days=4)
    # Get today's date range
    # TODO: Commenting this
    # today = datetime.today().date()

    min_dt = datetime.combine(today, time.min)  # 00:00:00
    max_dt = datetime.combine(today, time.max)  # 23:59:59.999999

    start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info("Running QRadarTasks.sync_daily_event_counts_for_admin() task")

        for domain_id in db_ids:
            query = IBMQradarConstants.AQL_QUERY_FOR_DAILY_EVENT_COUNTS.format(
                domain_id=domain_id,
                start_time=start_str,
                end_time=end_str,
            )

            logger.info(
                f"Executing DAILY EVENT COUNTS AQL for domain {domain_id} ({start_str} → {end_str})"
            )

            search_id = ibm_qradar._get_do_aql_query(query=query)
            data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)

            if not data_ready:
                logger.warning(
                    f"No daily event count data returned for domain {domain_id}"
                )
                continue

            results = ibm_qradar._get_eps_results_by_search_id(search_id)
            transformed = ibm_qradar._transform_daily_event_count_data(
                results, integration_id, domain_id, date=start_str
            )

            if transformed:
                ibm_qradar._insert_daily_event_count_data(transformed)

@shared_task
def sync_successful_logons_for_admin(
    username, password, ip_address, port, integration_id
):
    from datetime import datetime, time  # Import inside function

    db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

    # Get today's date range
    today = datetime.today().date()
    min_dt = datetime.combine(today, time.min)
    max_dt = datetime.combine(today, time.max)

    start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info("Running QRadarTasks.sync_successful_logons_for_admin() task")

        for domain_id in db_ids:
            query = IBMQradarConstants.AQL_QUERY_FOR_SUCCESSFUL_LOGONS.format(
                domain_id=domain_id,
                start_time=start_str,
                end_time=end_str,
            )

            logger.info(
                f"Executing SUCCESSFUL LOGONS AQL for domain {domain_id} ({start_str} → {end_str})"
            )

            search_id = ibm_qradar._get_do_aql_query(query=query)
            data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)

            if not data_ready:
                logger.warning(
                    f"No successful logon data returned for domain {domain_id}"
                )
                continue

            results = ibm_qradar._get_eps_results_by_search_id(search_id)
            transformed = ibm_qradar._transform_successful_logon_data(
                results, integration_id, domain_id, today
            )

            if transformed:
                ibm_qradar._insert_successful_logon_data(transformed)


@shared_task
def sync_successful_logons():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_successful_logons_for_admin.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )


# ibm_qradar_task.py
@shared_task
def sync_remote_users_count_for_admin(
    username, password, ip_address, port, integration_id
):
    from datetime import datetime, time  # Import inside function

    db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

    # Get today's date range
    today = datetime.today().date()
    min_dt = datetime.combine(today, time.min)
    max_dt = datetime.combine(today, time.max)

    start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info("Running QRadarTasks.sync_remote_users_count_for_admin() task")

        for domain_id in db_ids:
            query = IBMQradarConstants.AQL_QUERY_FOR_REMOTE_USERS_COUNT.format(
                domain_id=domain_id,
                start_time=start_str,
                end_time=end_str,
            )

            logger.info(
                f"Executing REMOTE USERS COUNT AQL for domain {domain_id} ({start_str} → {end_str})"
            )

            search_id = ibm_qradar._get_do_aql_query(query=query)
            data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)

            if not data_ready:
                logger.warning(f"No remote users data returned for domain {domain_id}")
                continue

            results = ibm_qradar._get_eps_results_by_search_id(search_id)
            transformed = ibm_qradar._transform_remote_users_data(
                results, integration_id, domain_id, today
            )

            if transformed:
                ibm_qradar._insert_remote_users_data(transformed)


@shared_task
def sync_remote_users_count():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_remote_users_count_for_admin.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )


@shared_task
def sync_ibm_qradar_daily_sync():
    # logger.info("Running sync_recon_event_counts() task")
    # sync_recon_event_counts.delay()                            DONE
    # logger.info("Running sync_correlated_event_counts() task")
    # sync_correlated_event_counts.delay()
    # logger.info("Running sync_weekly_correlated_event_counts() task")
    # sync_weekly_correlated_event_counts.delay()
    # logger.info("Running sync_suspicious_event_counts() task")
    # sync_suspicious_event_counts.delay()                        DONE
    # logger.info("Running sync_dos_event_counts() task")
    # sync_dos_event_counts.delay()                               DONE
    # logger.info("Running sync_top_dos_event_counts() task")
    # sync_top_dos_event_counts.delay()                           DONE
    # logger.info("Running sync_daily_event_counts() task")
    # sync_daily_event_counts.delay()                             DONE
    # logger.info("Running sync_top_alert_event_counts() task")
    # sync_top_alert_event_counts.delay()                         DONE
    # logger.info("Running sync_daily_closure_reason_counts() task")
    # sync_daily_closure_reason_counts.delay()                    DONE
    # logger.info("Running sync_monthly_avg_eps() task")
    # sync_monthly_avg_eps.delay()                                DONE
    # logger.info("Running sync_last_month_avg_eps() task")
    # sync_last_month_avg_eps.delay()                             DONE
    # logger.info("Running sync_weekly_avg_eps() task")
    # sync_weekly_avg_eps.delay()                                 DONE
    # logger.info("Running sync_total_traffic() task")
    # sync_total_traffic.delay()                                  DONE
    # logger.info("Running sync_destination_address_counts() task")
    # sync_destination_address_counts.delay()                     DONE
    # logger.info("Running sync_top_destination_connection_counts() task")         DONE
    # sync_top_destination_connection_counts.delay()
    logger.info("Running sync_daily_event_counts_logs() task")
    sync_daily_event_counts_logs.delay()
