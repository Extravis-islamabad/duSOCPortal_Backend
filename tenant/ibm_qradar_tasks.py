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
    SourceIPGeoLocation,
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
def sync_top_high_level_category_count(
    username: str, password: str, ip_address: str, port: str, integration_id: int
):
    start = time.time()
    logger.info("Running QRadarTasks.sync_top_high_level_category_count() task")
    try:
        with IBMQradar(
            username=username, password=password, ip_address=ip_address, port=port
        ) as ibm_qradar:
            search_id = ibm_qradar._get_do_aql_query(
                query=IBMQradarConstants.AQL_QUERY_FOR_DOMAIN_EVENTS_AEP
            )
            flag = ibm_qradar._check_eps_results_by_search_id(search_id=search_id)
            if not flag:
                logger.warning(
                    f"IBM QRadar EPS sync failed for integration {integration_id}"
                )
                return
            data = ibm_qradar._get_eps_results_by_search_id(search_id=search_id)
            transformed_data = (
                ibm_qradar._transform_high_level_category_data_from_named_fields(data)
            )
            if transformed_data:
                ibm_qradar._insert_high_level_category_counts(transformed_data)
                logger.info(
                    "Completed QRadarTasks.sync_top_high_level_category_count() task"
                )
                logger.info(
                    f"QRadarTasks.sync_top_high_level_category_count() task took {time.time() - start} seconds"
                )
    except Exception as e:
        logger.error(
            f"Unexpected error in sync_top_high_level_category_count(): {str(e)}"
        )


@shared_task
def sync_category_wise_data_count(
    username: str, password: str, ip_address: str, port: str, integration_id: int
):
    start = time.time()
    logger.info("Running QRadarTasks.sync_category_wise_data_count() task")
    try:
        with IBMQradar(
            username=username, password=password, ip_address=ip_address, port=port
        ) as ibm_qradar:
            search_id = ibm_qradar._get_do_aql_query(
                query=IBMQradarConstants.AQL_QUERY_FOR_DOMAIN_WISE_DATA
            )
            flag = ibm_qradar._check_eps_results_by_search_id(search_id=search_id)
            if not flag:
                logger.warning(
                    f"IBM QRadar EPS sync failed for integration {integration_id}"
                )
                return
            data = ibm_qradar._get_eps_results_by_search_id(search_id=search_id)
            transformed_data = (
                ibm_qradar._transform_category_wise_data_from_named_fields(data)
            )
            if transformed_data:
                ibm_qradar._insert_category_wise_data(transformed_data)
                logger.info(
                    "Completed QRadarTasks.sync_category_wise_data_count() task"
                )
                logger.info(
                    f"QRadarTasks.sync_category_wise_data_count() task took {time.time() - start} seconds"
                )
    except Exception as e:
        logger.error(f"Unexpected error in sync_category_wise_data_count(): {str(e)}")


@shared_task
def sync_sensitive_count_wise_data(
    username: str, password: str, ip_address: str, port: str, integration_id: int
):
    start = time.time()
    logger.info("Running QRadarTasks.sync_sensitive_count_wise_data() task")
    try:
        with IBMQradar(
            username=username, password=password, ip_address=ip_address, port=port
        ) as ibm_qradar:
            search_id = ibm_qradar._get_do_aql_query(
                query=IBMQradarConstants.AQL_QUERY_FOR_SENITIVE_DATA
            )
            flag = ibm_qradar._check_eps_results_by_search_id(search_id=search_id)
            if not flag:
                logger.warning(
                    f"IBM QRadar EPS sync failed for integration {integration_id}"
                )
                return
            data = ibm_qradar._get_eps_results_by_search_id(search_id=search_id)
            transformed_data = ibm_qradar._transform_sensitive_data_from_named_fields(
                data
            )
            if transformed_data:
                ibm_qradar._insert_sensitive_data(transformed_data)
                logger.info(
                    "Completed QRadarTasks.sync_sensitive_count_wise_data() task"
                )
                logger.info(
                    f"QRadarTasks.sync_sensitive_count_wise_data() task took {time.time() - start} seconds"
                )
    except Exception as e:
        logger.error(f"Unexpected error in sync_sensitive_count_wise_data(): {str(e)}")


@shared_task
def sync_correlated_events_data(
    username: str, password: str, ip_address: str, port: str, integration_id: int
):
    start = time.time()
    logger.info("Running QRadarTasks.sync_correlated_events_data() task")
    try:
        with IBMQradar(
            username=username, password=password, ip_address=ip_address, port=port
        ) as ibm_qradar:
            # search_id = ibm_qradar._get_do_aql_query(
            #     query=IBMQradarConstants.AQL_QUERY_FOR_CORRELATED_EVENTS_DATA
            # )
            # flag = ibm_qradar._check_eps_results_by_search_id(search_id=search_id)
            # if not flag:
            #     logger.warning(
            #         f"IBM QRadar EPS sync failed for integration {integration_id}"
            #     )
            #     return
            # data = ibm_qradar._get_eps_results_by_search_id(search_id=search_id)
            data = {
                "events": [
                    {
                        "startTime": "2025-07-24 04:02",
                        "DOMAIN NAME": "DuTelecom",
                        "Event Name": "UBA : User Attempt to Use a Suspended Account",
                        "Magnitude (Maximum)": 7.0,
                        "Event Count (Sum)": 9156.0,
                        "Count": 9156.0,
                    },
                    {
                        "startTime": "2025-07-24 04:01",
                        "DOMAIN NAME": "DuTelecom",
                        "Event Name": "UBA : Detect Insecure Or Non-Standard Protocol",
                        "Magnitude (Maximum)": 8.0,
                        "Event Count (Sum)": 4283.0,
                        "Count": 4283.0,
                    },
                    {
                        "startTime": "2025-07-24 04:03",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "UBA : Large number of denied access events towards external domain",
                        "Magnitude (Maximum)": 7.0,
                        "Event Count (Sum)": 1087.0,
                        "Count": 1087.0,
                    },
                    {
                        "startTime": "2025-07-24 04:01",
                        "DOMAIN NAME": "ADGM",
                        "Event Name": "UBA : User Access from Multiple Hosts",
                        "Magnitude (Maximum)": 7.0,
                        "Event Count (Sum)": 509.0,
                        "Count": 509.0,
                    },
                    {
                        "startTime": "2025-07-24 04:02",
                        "DOMAIN NAME": "ADGM",
                        "Event Name": "ADGM-TrendMicro-Reconnaissance Detected Network or Port Scan",
                        "Magnitude (Maximum)": 8.0,
                        "Event Count (Sum)": 395.0,
                        "Count": 395.0,
                    },
                    {
                        "startTime": "2025-07-24 04:03",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "UBA : Browsed to Information Technology Website",
                        "Magnitude (Maximum)": 4.0,
                        "Event Count (Sum)": 371.0,
                        "Count": 371.0,
                    },
                    {
                        "startTime": "2025-07-24 04:03",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "Non-Mail Server Sending Mail to Servers Categorized as SPAM",
                        "Magnitude (Maximum)": 6.0,
                        "Event Count (Sum)": 314.0,
                        "Count": 314.0,
                    },
                    {
                        "startTime": "2025-07-24 01:47",
                        "DOMAIN NAME": "Tabreed",
                        "Event Name": "UBA : Remote access hole in corporate firewall",
                        "Magnitude (Maximum)": 8.0,
                        "Event Count (Sum)": 253.0,
                        "Count": 253.0,
                    },
                    {
                        "startTime": "2025-07-24 04:02",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "AEP-XDR Defender-Alerts",
                        "Magnitude (Maximum)": 8.0,
                        "Event Count (Sum)": 198.0,
                        "Count": 198.0,
                    },
                    {
                        "startTime": "2025-07-24 04:04",
                        "DOMAIN NAME": "Tabreed",
                        "Event Name": "UBA : Data Loss Possible",
                        "Magnitude (Maximum)": 7.0,
                        "Event Count (Sum)": 90.0,
                        "Count": 90.0,
                    },
                    {
                        "startTime": "2025-07-24 04:03",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "AEP-O365-Spam email received",
                        "Magnitude (Maximum)": 8.0,
                        "Event Count (Sum)": 66.0,
                        "Count": 66.0,
                    },
                    {
                        "startTime": "2025-07-24 12:59",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "UBA : Browsed to Communications Website",
                        "Magnitude (Maximum)": 4.0,
                        "Event Count (Sum)": 54.0,
                        "Count": 54.0,
                    },
                    {
                        "startTime": "2025-07-24 12:59",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "UBA : Browsed to Business/Service Website",
                        "Magnitude (Maximum)": 5.0,
                        "Event Count (Sum)": 38.0,
                        "Count": 38.0,
                    },
                    {
                        "startTime": "2025-07-24 12:58",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "AEP-Firewall-Outbound allowed traffic towards malware IP",
                        "Magnitude (Maximum)": 7.0,
                        "Event Count (Sum)": 35.0,
                        "Count": 35.0,
                    },
                    {
                        "startTime": "2025-07-24 04:05",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "UBA : Browsed to Entertainment Website",
                        "Magnitude (Maximum)": 4.0,
                        "Event Count (Sum)": 34.0,
                        "Count": 34.0,
                    },
                    {
                        "startTime": "2025-07-24 12:58",
                        "DOMAIN NAME": "Tabreed",
                        "Event Name": "UBA : Browsed to Uncategorized Website",
                        "Magnitude (Maximum)": 4.0,
                        "Event Count (Sum)": 32.0,
                        "Count": 32.0,
                    },
                    {
                        "startTime": "2025-07-24 02:19",
                        "DOMAIN NAME": "Tabreed",
                        "Event Name": "Suspicious Valid Accounts Logon",
                        "Magnitude (Maximum)": 6.0,
                        "Event Count (Sum)": 32.0,
                        "Count": 32.0,
                    },
                    {
                        "startTime": "2025-07-24 02:55",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "Remote ICMP Scanner Detected",
                        "Magnitude (Maximum)": 3.0,
                        "Event Count (Sum)": 29.0,
                        "Count": 29.0,
                    },
                    {
                        "startTime": "2025-07-24 01:59",
                        "DOMAIN NAME": "Tabreed",
                        "Event Name": "Tabreed-DLP-Removable Media",
                        "Magnitude (Maximum)": 8.0,
                        "Event Count (Sum)": 20.0,
                        "Count": 20.0,
                    },
                    {
                        "startTime": "2025-07-24 02:55",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "Remote Web Scanner Detected",
                        "Magnitude (Maximum)": 3.0,
                        "Event Count (Sum)": 12.0,
                        "Count": 12.0,
                    },
                    {
                        "startTime": "2025-07-24 12:23",
                        "DOMAIN NAME": "Tabreed",
                        "Event Name": "TABREED-Windows-Privilege Escalation Followed By Group Policy Modification",
                        "Magnitude (Maximum)": 7.0,
                        "Event Count (Sum)": 11.0,
                        "Count": 11.0,
                    },
                    {
                        "startTime": "2025-07-24 03:54",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "UBA : Detected Activity from a Locked Machine",
                        "Magnitude (Maximum)": 4.0,
                        "Event Count (Sum)": 10.0,
                        "Count": 10.0,
                    },
                    {
                        "startTime": "2025-07-24 07:02",
                        "DOMAIN NAME": "Tabreed",
                        "Event Name": "Potential Mailto Ransomware Behaviour (Windows)",
                        "Magnitude (Maximum)": 7.0,
                        "Event Count (Sum)": 9.0,
                        "Count": 9.0,
                    },
                    {
                        "startTime": "2025-07-23 11:55",
                        "DOMAIN NAME": "ADGM",
                        "Event Name": "Test-ADGM-Local L2L Suspicious Probe Events Detected",
                        "Magnitude (Maximum)": 10.0,
                        "Event Count (Sum)": 7.0,
                        "Count": 7.0,
                    },
                    {
                        "startTime": "2025-07-24 06:22",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "AEP-Device not reporting",
                        "Magnitude (Maximum)": 7.0,
                        "Event Count (Sum)": 5.0,
                        "Count": 5.0,
                    },
                    {
                        "startTime": "2025-07-24 02:38",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "UBA : Browsed to Education Website",
                        "Magnitude (Maximum)": 4.0,
                        "Event Count (Sum)": 4.0,
                        "Count": 4.0,
                    },
                    {
                        "startTime": "2025-07-24 12:09",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "Credential Dumping Activity",
                        "Magnitude (Maximum)": 8.0,
                        "Event Count (Sum)": 4.0,
                        "Count": 4.0,
                    },
                    {
                        "startTime": "2025-07-24 10:42",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "AEP-EntraID-Global Administrator Role Assignment",
                        "Magnitude (Maximum)": 6.0,
                        "Event Count (Sum)": 4.0,
                        "Count": 4.0,
                    },
                    {
                        "startTime": "2025-07-24 04:03",
                        "DOMAIN NAME": "Tabreed",
                        "Event Name": "Tabreed-PaloAlto-Successfull login from Unknown User",
                        "Magnitude (Maximum)": 6.0,
                        "Event Count (Sum)": 2.0,
                        "Count": 2.0,
                    },
                    {
                        "startTime": "2025-07-24 11:02",
                        "DOMAIN NAME": "Tabreed",
                        "Event Name": "Tabreed-Suspicious Activity Followed by Endpoint Administration Task",
                        "Magnitude (Maximum)": 7.0,
                        "Event Count (Sum)": 2.0,
                        "Count": 2.0,
                    },
                    {
                        "startTime": "2025-07-23 10:54",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "AEP-CyberArkVault- High Volume of Password Retrievals  of PVWA users for Non business hours",
                        "Magnitude (Maximum)": 7.0,
                        "Event Count (Sum)": 2.0,
                        "Count": 2.0,
                    },
                    {
                        "startTime": "2025-07-24 02:15",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "AEP-CyberArkVault- High Volume of Password Retrievals  of PVWA users",
                        "Magnitude (Maximum)": 7.0,
                        "Event Count (Sum)": 2.0,
                        "Count": 2.0,
                    },
                    {
                        "startTime": "2025-07-23 11:54",
                        "DOMAIN NAME": "ADGM",
                        "Event Name": "ADGM-Linux-Multiple SSH Login failures from same IP",
                        "Magnitude (Maximum)": 8.0,
                        "Event Count (Sum)": 2.0,
                        "Count": 2.0,
                    },
                    {
                        "startTime": "2025-07-23 09:30",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "Remote IRC Scanner Detected",
                        "Magnitude (Maximum)": 2.0,
                        "Event Count (Sum)": 1.0,
                        "Count": 1.0,
                    },
                    {
                        "startTime": "2025-07-24 08:03",
                        "DOMAIN NAME": "Tabreed",
                        "Event Name": "TABREED-Threat Intel - X-Force - Internal Host Communicating with Host Categorized as Anonymizer",
                        "Magnitude (Maximum)": 8.0,
                        "Event Count (Sum)": 1.0,
                        "Count": 1.0,
                    },
                    {
                        "startTime": "2025-07-24 12:06",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "Programming Environment Spawned by a Suspicious Process",
                        "Magnitude (Maximum)": 6.0,
                        "Event Count (Sum)": 1.0,
                        "Count": 1.0,
                    },
                    {
                        "startTime": "2025-07-24 07:11",
                        "DOMAIN NAME": "Tabreed",
                        "Event Name": "Tabreed-Host Port Scan Detected by Remote Host",
                        "Magnitude (Maximum)": 4.0,
                        "Event Count (Sum)": 1.0,
                        "Count": 1.0,
                    },
                    {
                        "startTime": "2025-07-23 05:42",
                        "DOMAIN NAME": "ADGM",
                        "Event Name": "ADGM-Linux-Multiple SSH Login failures for same username",
                        "Magnitude (Maximum)": 8.0,
                        "Event Count (Sum)": 1.0,
                        "Count": 1.0,
                    },
                    {
                        "startTime": "2025-07-24 03:07",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "AEP-O365-Compliance Policy Violation",
                        "Magnitude (Maximum)": 6.0,
                        "Event Count (Sum)": 1.0,
                        "Count": 1.0,
                    },
                    {
                        "startTime": "2025-07-23 11:42",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "AEP-CyberArkVault-Abnormal Password Change Frequency",
                        "Magnitude (Maximum)": 7.0,
                        "Event Count (Sum)": 1.0,
                        "Count": 1.0,
                    },
                    {
                        "startTime": "2025-07-24 10:33",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "AEP-Firewall-Outbound denied traffic towards malware IP",
                        "Magnitude (Maximum)": 7.0,
                        "Event Count (Sum)": 1.0,
                        "Count": 1.0,
                    },
                    {
                        "startTime": "2025-07-24 07:25",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "AEP-Firewall-Inbound denied traffic from malware IP",
                        "Magnitude (Maximum)": 6.0,
                        "Event Count (Sum)": 1.0,
                        "Count": 1.0,
                    },
                    {
                        "startTime": "2025-07-24 03:31",
                        "DOMAIN NAME": "AEP",
                        "Event Name": "AEP-Firewall-Multiple Login Failures for Single Username",
                        "Magnitude (Maximum)": 7.0,
                        "Event Count (Sum)": 1.0,
                        "Count": 1.0,
                    },
                    {
                        "startTime": "2025-07-24 04:08",
                        "DOMAIN NAME": "Tabreed",
                        "Event Name": "Linux System Shutdown/Reboot",
                        "Magnitude (Maximum)": 3.0,
                        "Event Count (Sum)": 1.0,
                        "Count": 1.0,
                    },
                    {
                        "startTime": "2025-07-24 12:32",
                        "DOMAIN NAME": "EMFA",
                        "Event Name": "DU-Windows-Multiple Login Failures from the Same Source",
                        "Magnitude (Maximum)": 7.0,
                        "Event Count (Sum)": 1.0,
                        "Count": 1.0,
                    },
                    {
                        "startTime": "2025-07-23 11:59",
                        "DOMAIN NAME": "Tabreed",
                        "Event Name": "Tabreed-Linux-Privilege Escalation Succeded",
                        "Magnitude (Maximum)": 8.0,
                        "Event Count (Sum)": 1.0,
                        "Count": 1.0,
                    },
                ]
            }
            transformed_data = (
                ibm_qradar._transform_corelated_events_data_from_named_fields(
                    data.get("events")
                )
            )
            if transformed_data:
                ibm_qradar._insert_corelated_events_data(transformed_data)
                logger.info("Completed QRadarTasks.sync_correlated_events_data() task")
                logger.info(
                    f"QRadarTasks.sync_correlated_events_data() task took {time.time() - start} seconds"
                )
    except Exception as e:
        logger.error(f"Unexpected error in sync_correlated_events_data(): {str(e)}")


@shared_task
def sync_aep_entra_failures_data(
    username: str, password: str, ip_address: str, port: str, integration_id: int
):
    start = time.time()
    logger.info("Running QRadarTasks.sync_aep_entra_failures_data() task")
    try:
        with IBMQradar(
            username=username, password=password, ip_address=ip_address, port=port
        ) as ibm_qradar:
            # search_id = ibm_qradar._get_do_aql_query(
            #     query=IBMQradarConstants.AQL_QUERY_FOR_AEP_ENTRA_FAILURES_DATA
            # )
            # flag = ibm_qradar._check_eps_results_by_search_id(search_id=search_id)
            # if not flag:
            #     logger.warning(
            #         f"IBM QRadar EPS sync failed for integration {integration_id}"
            #     )
            #     return

            # data = ibm_qradar._get_eps_results_by_search_id(search_id=search_id)
            data = {
                "events": [
                    {
                        "startTime": "2025-07-24 04:02",
                        "DOMAIN NAME": "AEP",
                        "User": "Andrew McCormack",
                        "Low Level Category": "User Account Disabled",
                        "Event Count (Sum)": 2374.0,
                        "Count": 2374.0,
                    },
                    {
                        "startTime": "2025-07-24 04:02",
                        "DOMAIN NAME": "AEP",
                        "User": "Jan Pilbauer",
                        "Low Level Category": "Web Service Login Failed",
                        "Event Count (Sum)": 1072.0,
                        "Count": 1072.0,
                    },
                    {
                        "startTime": "2025-07-24 04:02",
                        "DOMAIN NAME": "AEP",
                        "User": "Furkan Du Team",
                        "Low Level Category": "User Account Disabled",
                        "Event Count (Sum)": 410.0,
                        "Count": 410.0,
                    },
                    {
                        "startTime": "2025-07-24 04:02",
                        "DOMAIN NAME": "AEP",
                        "User": "Prajith Gopidas",
                        "Low Level Category": "Web Service Login Failed",
                        "Event Count (Sum)": 341.0,
                        "Count": 341.0,
                    },
                    {
                        "startTime": "2025-07-24 04:02",
                        "DOMAIN NAME": "AEP",
                        "User": "Zaynab Al Blooshi",
                        "Low Level Category": "User Login Failure",
                        "Event Count (Sum)": 286.0,
                        "Count": 286.0,
                    },
                    {
                        "startTime": "2025-07-24 04:02",
                        "DOMAIN NAME": "AEP",
                        "User": "Muhseen Mustafa",
                        "Low Level Category": "User Login Failure",
                        "Event Count (Sum)": 220.0,
                        "Count": 220.0,
                    },
                    {
                        "startTime": "2025-07-24 04:02",
                        "DOMAIN NAME": "AEP",
                        "User": "Prasad Kishor Patil",
                        "Low Level Category": "User Login Failure",
                        "Event Count (Sum)": 166.0,
                        "Count": 166.0,
                    },
                    {
                        "startTime": "2025-07-24 03:57",
                        "DOMAIN NAME": "AEP",
                        "User": "Information Security",
                        "Low Level Category": "User Login Failure",
                        "Event Count (Sum)": 120.0,
                        "Count": 120.0,
                    },
                    {
                        "startTime": "2025-07-24 12:52",
                        "DOMAIN NAME": "AEP",
                        "User": "Procurement",
                        "Low Level Category": "Web Service Login Failed",
                        "Event Count (Sum)": 117.0,
                        "Count": 117.0,
                    },
                    {
                        "startTime": "2025-07-24 02:42",
                        "DOMAIN NAME": "AEP",
                        "User": "Jerit John Abraham",
                        "Low Level Category": "Web Service Login Failed",
                        "Event Count (Sum)": 100.0,
                        "Count": 100.0,
                    },
                ]
            }

            transformed_data = (
                ibm_qradar._transform_aep_authentication_data_from_named_fields(
                    data.get("events")
                )
            )
            if transformed_data:
                ibm_qradar._insert_aep_authentication_data(transformed_data)
                logger.info("Completed QRadarTasks.sync_aep_entra_failures_data() task")
                logger.info(
                    f"QRadarTasks.sync_aep_entra_failures_data() task took {time.time() - start} seconds"
                )
    except Exception as e:
        logger.error(f"Unexpected error in sync_aep_entra_failures_data(): {str(e)}")


@shared_task
def sync_allowed_outbound_data(
    username: str, password: str, ip_address: str, port: str, integration_id: int
):
    start = time.time()
    logger.info("Running QRadarTasks.sync_allowed_outbound_data() task")
    try:
        with IBMQradar(
            username=username, password=password, ip_address=ip_address, port=port
        ) as ibm_qradar:
            # search_id = ibm_qradar._get_do_aql_query(
            #     query=IBMQradarConstants.AQL_QUERY_FOR_ALLOWED_OUTBOUND_DATA
            # )
            # flag = ibm_qradar._check_eps_results_by_search_id(search_id=search_id)
            # if not flag:
            #     logger.warning(
            #         f"IBM QRadar EPS sync failed for integration {integration_id}"
            #     )
            #     return
            # data = ibm_qradar._get_eps_results_by_search_id(search_id=search_id)
            data = {
                "events": [
                    {
                        "startTime": "2025-07-24 04:05",
                        "domainname_domainid": "ADGM",
                        "Source IP": "172.24.153.20",
                        "Destination IP": "94.200.200.200",
                        "Destination Port": 53,
                        "Destination Geographic Country/Region": "Asia.UnitedArabEmirates",
                        "Event Count (Sum)": 4428943.0,
                        "Count": 16675.0,
                    },
                    {
                        "startTime": "2025-07-24 04:06",
                        "domainname_domainid": "EMFA",
                        "Source IP": "172.24.156.10",
                        "Destination IP": "127.0.0.1",
                        "Destination Port": 0,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 4374628.0,
                        "Count": 4374628.0,
                    },
                    {
                        "startTime": "2025-07-24 04:06",
                        "domainname_domainid": "EMFA",
                        "Source IP": "172.24.154.10",
                        "Destination IP": "127.0.0.1",
                        "Destination Port": 0,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 4372283.0,
                        "Count": 4372283.0,
                    },
                    {
                        "startTime": "2025-07-24 04:04",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.108.4.198",
                        "Destination IP": "4.150.240.10",
                        "Destination Port": 443,
                        "Destination Geographic Country/Region": "NorthAmerica.UnitedStates",
                        "Event Count (Sum)": 400824.0,
                        "Count": 7994.0,
                    },
                    {
                        "startTime": "2025-07-24 01:58",
                        "domainname_domainid": "Tabreed",
                        "Source IP": "10.83.180.44",
                        "Destination IP": "10.83.180.44",
                        "Destination Port": 0,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 330638.0,
                        "Count": 11496.0,
                    },
                    {
                        "startTime": "2025-07-24 02:58",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.110.16.60",
                        "Destination IP": "10.108.4.198",
                        "Destination Port": 9995,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 276192.0,
                        "Count": 5760.0,
                    },
                    {
                        "startTime": "2025-07-24 04:06",
                        "domainname_domainid": "Tabreed",
                        "Source IP": "10.100.180.52",
                        "Destination IP": "23.208.212.240",
                        "Destination Port": 443,
                        "Destination Geographic Country/Region": "Asia.UnitedArabEmirates",
                        "Event Count (Sum)": 259530.0,
                        "Count": 13788.0,
                    },
                    {
                        "startTime": "2025-07-24 02:58",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.108.7.2",
                        "Destination IP": "10.108.7.1",
                        "Destination Port": 3784,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 199018.0,
                        "Count": 16418.0,
                    },
                    {
                        "startTime": "2025-07-24 02:58",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.108.7.6",
                        "Destination IP": "10.108.7.5",
                        "Destination Port": 3784,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 198762.0,
                        "Count": 16378.0,
                    },
                    {
                        "startTime": "2025-07-24 02:58",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.110.113.11",
                        "Destination IP": "10.108.4.198",
                        "Destination Port": 9995,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 184416.0,
                        "Count": 15894.0,
                    },
                    {
                        "startTime": "2025-07-24 04:01",
                        "domainname_domainid": "ADGM",
                        "Source IP": "172.24.155.4",
                        "Destination IP": "172.24.155.4",
                        "Destination Port": 0,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 147188.0,
                        "Count": 17156.0,
                    },
                    {
                        "startTime": "2025-07-24 04:05",
                        "domainname_domainid": "DuTelecom",
                        "Source IP": "10.225.148.149",
                        "Destination IP": "10.225.128.135",
                        "Destination Port": 53,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 123083.0,
                        "Count": 35959.0,
                    },
                    {
                        "startTime": "2025-07-24 02:58",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.110.16.1",
                        "Destination IP": "10.110.16.1",
                        "Destination Port": 5355,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 109172.0,
                        "Count": 15850.0,
                    },
                    {
                        "startTime": "2025-07-24 02:58",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.110.96.101",
                        "Destination IP": "10.110.96.1",
                        "Destination Port": 53,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 104076.0,
                        "Count": 14924.0,
                    },
                    {
                        "startTime": "2025-07-24 04:05",
                        "domainname_domainid": "ADGM",
                        "Source IP": "172.24.153.3",
                        "Destination IP": "94.200.200.200",
                        "Destination Port": 53,
                        "Destination Geographic Country/Region": "Asia.UnitedArabEmirates",
                        "Event Count (Sum)": 97402.0,
                        "Count": 13176.0,
                    },
                    {
                        "startTime": "2025-07-24 04:04",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.108.1.6",
                        "Destination IP": "10.108.1.5",
                        "Destination Port": 703,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 89169.0,
                        "Count": 8099.0,
                    },
                    {
                        "startTime": "2025-07-24 04:04",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.110.8.178",
                        "Destination IP": "94.200.200.200",
                        "Destination Port": 53,
                        "Destination Geographic Country/Region": "Asia.UnitedArabEmirates",
                        "Event Count (Sum)": 86849.0,
                        "Count": 18177.0,
                    },
                    {
                        "startTime": "2025-07-24 02:59",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.110.8.176",
                        "Destination IP": "94.200.200.200",
                        "Destination Port": 53,
                        "Destination Geographic Country/Region": "Asia.UnitedArabEmirates",
                        "Event Count (Sum)": 79387.0,
                        "Count": 16488.0,
                    },
                    {
                        "startTime": "2025-07-24 04:04",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.110.80.101",
                        "Destination IP": "10.110.81.101",
                        "Destination Port": 443,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 72054.0,
                        "Count": 6575.0,
                    },
                    {
                        "startTime": "2025-07-24 04:04",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.110.81.101",
                        "Destination IP": "10.110.82.101",
                        "Destination Port": 3306,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 69276.0,
                        "Count": 5408.0,
                    },
                    {
                        "startTime": "2025-07-24 04:04",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.110.50.124",
                        "Destination IP": "20.212.88.141",
                        "Destination Port": 80,
                        "Destination Geographic Country/Region": "Asia.Singapore",
                        "Event Count (Sum)": 66726.0,
                        "Count": 14608.0,
                    },
                    {
                        "startTime": "2025-07-24 01:58",
                        "domainname_domainid": "Tabreed",
                        "Source IP": "10.83.180.210",
                        "Destination IP": "94.200.200.200",
                        "Destination Port": 53,
                        "Destination Geographic Country/Region": "Asia.UnitedArabEmirates",
                        "Event Count (Sum)": 66568.0,
                        "Count": 13059.0,
                    },
                    {
                        "startTime": "2025-07-24 04:04",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.110.50.121",
                        "Destination IP": "20.212.88.141",
                        "Destination Port": 80,
                        "Destination Geographic Country/Region": "Asia.Singapore",
                        "Event Count (Sum)": 66289.0,
                        "Count": 14616.0,
                    },
                    {
                        "startTime": "2025-07-24 04:04",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.110.50.113",
                        "Destination IP": "20.212.88.141",
                        "Destination Port": 80,
                        "Destination Geographic Country/Region": "Asia.Singapore",
                        "Event Count (Sum)": 66243.0,
                        "Count": 14674.0,
                    },
                    {
                        "startTime": "2025-07-24 04:04",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.110.50.125",
                        "Destination IP": "20.212.88.141",
                        "Destination Port": 80,
                        "Destination Geographic Country/Region": "Asia.Singapore",
                        "Event Count (Sum)": 65317.0,
                        "Count": 14533.0,
                    },
                    {
                        "startTime": "2025-07-24 08:58",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.110.32.113",
                        "Destination IP": "10.110.32.255",
                        "Destination Port": 137,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 65072.0,
                        "Count": 5448.0,
                    },
                    {
                        "startTime": "2025-07-24 04:06",
                        "domainname_domainid": "ADGM",
                        "Source IP": "172.24.151.21",
                        "Destination IP": "172.24.151.21",
                        "Destination Port": 0,
                        "Destination Geographic Country/Region": "Asia.UnitedArabEmirates",
                        "Event Count (Sum)": 63629.0,
                        "Count": 11005.0,
                    },
                    {
                        "startTime": "2025-07-24 02:58",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.110.16.27",
                        "Destination IP": "160.223.172.11",
                        "Destination Port": 443,
                        "Destination Geographic Country/Region": "NorthAmerica.UnitedStates",
                        "Event Count (Sum)": 57248.0,
                        "Count": 14266.0,
                    },
                    {
                        "startTime": "2025-07-24 02:58",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.110.16.26",
                        "Destination IP": "160.223.172.11",
                        "Destination Port": 443,
                        "Destination Geographic Country/Region": "NorthAmerica.UnitedStates",
                        "Event Count (Sum)": 57240.0,
                        "Count": 14256.0,
                    },
                    {
                        "startTime": "2025-07-24 04:05",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.110.16.1",
                        "Destination IP": "10.110.16.1",
                        "Destination Port": 0,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 55815.0,
                        "Count": 14516.0,
                    },
                    {
                        "startTime": "2025-07-24 04:05",
                        "domainname_domainid": "ADGM",
                        "Source IP": "172.24.156.19",
                        "Destination IP": "172.24.156.19",
                        "Destination Port": 0,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 54317.0,
                        "Count": 10956.0,
                    },
                    {
                        "startTime": "2025-07-24 04:05",
                        "domainname_domainid": "ADGM",
                        "Source IP": "172.24.156.35",
                        "Destination IP": "172.24.155.3",
                        "Destination Port": 8081,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 53176.0,
                        "Count": 13294.0,
                    },
                    {
                        "startTime": "2025-07-24 04:05",
                        "domainname_domainid": "ADGM",
                        "Source IP": "172.24.156.35",
                        "Destination IP": "172.24.155.2",
                        "Destination Port": 8081,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 53176.0,
                        "Count": 13294.0,
                    },
                    {
                        "startTime": "2025-07-24 04:06",
                        "domainname_domainid": "ADGM",
                        "Source IP": "172.24.154.35",
                        "Destination IP": "172.24.151.2",
                        "Destination Port": 8081,
                        "Destination Geographic Country/Region": "Asia.UnitedArabEmirates",
                        "Event Count (Sum)": 53172.0,
                        "Count": 13296.0,
                    },
                    {
                        "startTime": "2025-07-24 04:06",
                        "domainname_domainid": "ADGM",
                        "Source IP": "172.24.154.35",
                        "Destination IP": "172.24.150.3",
                        "Destination Port": 8081,
                        "Destination Geographic Country/Region": "Asia.UnitedArabEmirates",
                        "Event Count (Sum)": 53170.0,
                        "Count": 13294.0,
                    },
                    {
                        "startTime": "2025-07-24 04:05",
                        "domainname_domainid": "ADGM",
                        "Source IP": "172.24.154.35",
                        "Destination IP": "172.24.150.2",
                        "Destination Port": 8081,
                        "Destination Geographic Country/Region": "Asia.UnitedArabEmirates",
                        "Event Count (Sum)": 53170.0,
                        "Count": 13294.0,
                    },
                    {
                        "startTime": "2025-07-24 04:05",
                        "domainname_domainid": "ADGM",
                        "Source IP": "172.24.154.35",
                        "Destination IP": "172.24.151.3",
                        "Destination Port": 8081,
                        "Destination Geographic Country/Region": "Asia.UnitedArabEmirates",
                        "Event Count (Sum)": 52850.0,
                        "Count": 13294.0,
                    },
                    {
                        "startTime": "2025-07-24 04:05",
                        "domainname_domainid": "ADGM",
                        "Source IP": "172.24.155.4",
                        "Destination IP": "172.24.155.5",
                        "Destination Port": 0,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 51840.0,
                        "Count": 6015.0,
                    },
                    {
                        "startTime": "2025-07-24 04:04",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.110.17.31",
                        "Destination IP": "10.110.112.11",
                        "Destination Port": 1812,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 50433.0,
                        "Count": 5844.0,
                    },
                    {
                        "startTime": "2025-07-24 04:06",
                        "domainname_domainid": "Tabreed",
                        "Source IP": "10.100.180.52",
                        "Destination IP": "23.208.214.192",
                        "Destination Port": 443,
                        "Destination Geographic Country/Region": "Asia.UnitedArabEmirates",
                        "Event Count (Sum)": 50319.0,
                        "Count": 13106.0,
                    },
                    {
                        "startTime": "2025-07-24 12:59",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.110.33.106",
                        "Destination IP": "10.110.33.1",
                        "Destination Port": 53,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 45417.0,
                        "Count": 9433.0,
                    },
                    {
                        "startTime": "2025-07-24 04:06",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.110.32.113",
                        "Destination IP": "10.110.32.1",
                        "Destination Port": 53,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 44806.0,
                        "Count": 8581.0,
                    },
                    {
                        "startTime": "2025-07-24 04:05",
                        "domainname_domainid": "DuTelecom",
                        "Source IP": "10.225.148.149",
                        "Destination IP": "10.225.128.136",
                        "Destination Port": 53,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 44464.0,
                        "Count": 19170.0,
                    },
                    {
                        "startTime": "2025-07-24 04:04",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.108.6.29",
                        "Destination IP": "10.108.1.4",
                        "Destination Port": 53,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 44398.0,
                        "Count": 11231.0,
                    },
                    {
                        "startTime": "2025-07-24 04:04",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.110.50.122",
                        "Destination IP": "20.212.88.141",
                        "Destination Port": 80,
                        "Destination Geographic Country/Region": "Asia.Singapore",
                        "Event Count (Sum)": 43100.0,
                        "Count": 13879.0,
                    },
                    {
                        "startTime": "2025-07-24 02:59",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.81.73.57",
                        "Destination IP": "172.16.2.11",
                        "Destination Port": 514,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 42174.0,
                        "Count": 8010.0,
                    },
                    {
                        "startTime": "2025-07-24 04:04",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.108.6.32",
                        "Destination IP": "10.108.1.4",
                        "Destination Port": 53,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 41292.0,
                        "Count": 10633.0,
                    },
                    {
                        "startTime": "2025-07-24 04:06",
                        "domainname_domainid": "ADGM",
                        "Source IP": "172.24.150.7",
                        "Destination IP": "172.24.150.7",
                        "Destination Port": 0,
                        "Destination Geographic Country/Region": "Asia.UnitedArabEmirates",
                        "Event Count (Sum)": 40121.0,
                        "Count": 9023.0,
                    },
                    {
                        "startTime": "2025-07-24 02:58",
                        "domainname_domainid": "AEP",
                        "Source IP": "10.110.16.1",
                        "Destination IP": "10.110.16.1",
                        "Destination Port": 5353,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 38672.0,
                        "Count": 4435.0,
                    },
                    {
                        "startTime": "2025-07-24 04:05",
                        "domainname_domainid": "ADGM",
                        "Source IP": "172.24.156.35",
                        "Destination IP": "172.24.155.5",
                        "Destination Port": 5000,
                        "Destination Geographic Country/Region": "other",
                        "Event Count (Sum)": 38400.0,
                        "Count": 4803.0,
                    },
                ]
            }
            transformed_data = (
                ibm_qradar._transform_allowed_outbounds_data_from_named_fields(
                    data.get("events")
                )
            )
            if transformed_data:
                ibm_qradar._insert_allowed_outbounds_data(transformed_data)
                logger.info("Completed QRadarTasks.sync_allowed_outbound_data() task")
                logger.info(
                    f"QRadarTasks.sync_allowed_outbound_data() task took {time.time() - start} seconds"
                )
    except Exception as e:
        logger.error(f"Unexpected error in sync_aep_entra_failures_data(): {str(e)}")


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
def sync_parent_high_level_category():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_category_wise_data_count.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )


@shared_task
def sync_top_high_level_category_count_category():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_top_high_level_category_count.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )


# adding tasks for above AQL queries
@shared_task
def sync_event_log_assets_categogy():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )
    for result in results:
        sync_event_log_assets.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )


@shared_task
def sync_allowed_outbound_data_categogy():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_allowed_outbound_data.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )


@shared_task
def sync_aep_entra_failures_data_categogy():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )

    for result in results:
        sync_aep_entra_failures_data.delay(
            username=result.username,
            password=result.password,
            ip_address=result.ip_address,
            port=result.port,
            integration_id=result.integration.id,
        )


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
            ibm_qradar.backfill_offense_dates()


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
    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        logger.info("Running QRadarTasks.sync_eps_for_domain() task")
        search_id = ibm_qradar._get_do_aql_query(
            query=IBMQradarConstants.AQL_EPS_UPDATED_QUERY
        )
        flag = ibm_qradar._check_eps_results_by_search_id(search_id=search_id)
        if not flag:
            logger.warning(
                f"IBM QRadar EPS sync failed for integration {integration_id}"
            )
            return
        data = ibm_qradar._get_eps_results_by_search_id(search_id=search_id)
        transformed_data = ibm_qradar._transform_eps_data_from_named_fields(
            data_list=data, integration=integration_id
        )
        if transformed_data:
            ibm_qradar._insert_eps(transformed_data)

            logger.info("Completed QRadarTasks.sync_eps_for_domain() task")


@shared_task
def sync_geo_location_child(
    username: str, password: str, ip_address: str, port: int, integration_id: int
):
    SourceIPGeoLocation.objects.all().delete()
    logger.info("Running QRadarTasks.sync_geo_location_child() task")
    with IBMQradar(
        username=username, password=password, ip_address=ip_address, port=port
    ) as ibm_qradar:
        search_id = ibm_qradar._get_do_aql_query(
            query=IBMQradarConstants.AQL_QUERY_FOR_GEOLOCATION
        )
        flag = ibm_qradar._check_eps_results_by_search_id(search_id=search_id)
        if not flag:
            logger.warning(
                f"IBM QRadar.sync_geo_location_child() failed for for integration {integration_id}"
            )
            return

        data = ibm_qradar._get_eps_results_by_search_id(search_id=search_id)
        transformed_data = ibm_qradar.transform_geo_events(
            events=data, integration_id=integration_id
        )
        if transformed_data:
            ibm_qradar.insert_geo_events(transformed_data=transformed_data)

            logger.info("Completed QRadarTasks.sync_geo_location_child() task")


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
def sync_geo_location():
    results = IntegrationCredentials.objects.filter(
        integration__integration_type=IntegrationTypes.SIEM_INTEGRATION,
        integration__siem_subtype=SiemSubTypes.IBM_QRADAR,
        credential_type=CredentialTypes.USERNAME_PASSWORD,
    )
    for result in results:
        sync_geo_location_child.delay(
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
        # sync_eps_for_domain.delay(
        #     username=result.username,
        #     password=result.password,
        #     ip_address=result.ip_address,
        #     port=result.port,
        #     integration_id=result.integration.id,
        # )


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


# @shared_task
# def sync_event_count_for_admin(username, password, ip_address, port, integration_id):
#     from datetime import datetime, time  # Import inside function

#     db_ids = DuIbmQradarTenants.objects.values_list("db_id", flat=True)

#     # Get today's date with min and max time
#     today = datetime.today().date()
#     min_dt = datetime.combine(today, time.min)  # 00:00:00
#     max_dt = datetime.combine(today, time.max)  # 23:59:59.999999

#     # Format as "YYYY-MM-DD HH:MM:SS" for QRadar AQL
#     start_str = min_dt.strftime("%Y-%m-%d %H:%M:%S")
#     end_str = max_dt.strftime("%Y-%m-%d %H:%M:%S")

#     with IBMQradar(
#         username=username, password=password, ip_address=ip_address, port=port
#     ) as ibm_qradar:
#         logger.info("Running QRadarTasks.sync_event_count_for_admin() task")

#         for domain_id in db_ids:
#             query = IBMQradarConstants.AQL_QUERY_FOR_SUSPICIOUS_EVENTS.format(
#                 domain_id=domain_id, start_time=start_str, end_time=end_str
#             )
#             logger.info(
#                 f"Executing AQL for domain {domain_id} (From {start_str} To {end_str})"
#             )

#             search_id = ibm_qradar._get_do_aql_query(query=query)
#             data_ready = ibm_qradar._check_eps_results_by_search_id(search_id)

#             if not data_ready:
#                 logger.warning(f"No data returned for domain {domain_id}")
#                 continue

#             results = ibm_qradar._get_eps_results_by_search_id(search_id)
#             transformed = ibm_qradar._transform_event_count_data(
#                 results, integration_id, domain_id
#             )
#             if transformed:
#                 ibm_qradar._insert_event_count_data(transformed)


@shared_task
def sync_event_count_for_admin(username, password, ip_address, port, integration_id):
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
                results, integration_id, domain_id, date=start_str
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

        # Set date range (last 4 weeks from current date minus 2 days)
        now = datetime.now() - timedelta(days=1)
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
                        results, integration_id, domain_id, date=start_str
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


# @shared_task
# def sync_domain_events_data(
#     username, password, ip_address, port
# ):


# domain_names = DuIbmQradarTenants.objects.values_list("name", flat=True)
# print(domain_names)


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
    logger.info("Running sync_recon_event_counts() task")
    sync_ibm_event_counts.delay()
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
    # logger.info("Running sync_daily_event_counts_logs() task")    DONE
    # sync_daily_event_counts_logs.delay()
