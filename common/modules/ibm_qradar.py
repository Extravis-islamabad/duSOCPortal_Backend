import time

import pandas as pd
import requests
from django.db import transaction
from loguru import logger
from requests.auth import HTTPBasicAuth

from common.constants import IBMQradarConstants, SSLConstants
from common.utils import DBMappings
from tenant.models import (
    CorrelatedEventLog,
    CustomerEPS,
    DailyClosureReasonLog,
    DailyEventCountLog,
    DailyEventLog,
    DestinationAddressLog,
    DosEventLog,
    DuIbmQradarTenants,
    EventCountLog,
    IBMQradarAssests,
    IBMQradarEPS,
    IBMQradarEventCollector,
    IBMQradarLogSourceTypes,
    IBMQradarOffense,
    LastMonthAvgEpsLog,
    MonthlyAvgEpsLog,
    ReconEventLog,
    RemoteUsersCount,
    SuccessfulLogonEvent,
    SuspiciousEventLog,
    TopAlertEventLog,
    TopDestinationConnectionLog,
    TopDosEventLog,
    TotalEvents,
    TotalTrafficLog,
    WeeklyAvgEpsLog,
    WeeklyCorrelatedEventLog,
)


class IBMQradar:
    def __init__(self, username: str, password: str, ip_address: str, port: int):
        """
        Constructor for IBMQRadar class.

        :param username: The username to use when logging into the QRadar.
        :param password: The password to use when logging into the QRadar.
        :raises ValueError: If either the username or password are not set.
        """
        self.username = username
        self.password = password
        self.ip_address = ip_address
        self.port = port
        if (
            not self.username
            or not self.password
            or not self.ip_address
            or not self.port
        ):
            logger.error(
                "IBM QRadar both username, password ip_address and port are required"
            )
            raise ValueError(
                "Both username, password, ip_address and port are required"
            )

        self.base_url = self.get_base_url()

    def __enter__(self):
        """
        Enter the runtime context related to this object.

        This method logs the entry into the IBM QRadar context using the
        provided username and prepares the object for use with a context
        manager (e.g., with statement).

        :return: Returns self after logging the entry.
        """

        logger.info(f"Logging into IBM QRadar with username: {self.username}")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Exit the runtime context related to this object.

        This method logs the exit from the IBM QRadar context and
        performs any necessary cleanup.

        :param exc_type: The type of exception thrown, if any.
        :param exc_value: The value of the exception thrown, if any.
        :param traceback: The traceback of the exception thrown, if any.
        """
        logger.info("Logging out of IBM QRadar")

    def get_base_url(self):
        """
        Return the base URL of the IBM QRadar instance.

        :param ip_address: The IP address of the IBM QRadar instance.
        :param port: The port number of the IBM QRadar instance.
        :return: The base URL of the IBM QRadar instance.
        """
        if self.port != 80:
            return f"https://{self.ip_address}:{self.port}"
        return f"https://{self.ip_address}"

    def test_integration(self, timeout=SSLConstants.TIMEOUT):
        """
        Tests the integration with the IBM QRadar instance.

        This method sends an HTTP GET request to the IBM QRadar 'about' API endpoint
        using the credentials and base URL set in the IBMQradar class. It uses HTTP basic
        authentication. If the request is successful, it returns the parsed JSON response.
        If the request fails or an exception occurs, it logs an error and returns False or
        an empty list.

        :return: A dictionary containing 'about' information from the QRadar instance if
                the request is successful, otherwise False or an empty list.
        :raises: Logs any exceptions that occur during the request.
        """

        start = time.time()
        endpoint = f"{self.base_url}/{IBMQradarConstants.IBM_ABOUT_ENDPOINT}"
        try:
            response = requests.get(
                endpoint,
                auth=HTTPBasicAuth(
                    self.username,
                    self.password,
                ),
                verify=SSLConstants.VERIFY,  # TODO : Handle this to TRUE in production
                timeout=timeout,
            )
            if response.status_code != 200:
                logger.warning(
                    f"IBMQRadar.test_integration() return the status code {response.status_code}"
                )
                return
            data = response.json()
            logger.success(
                f"IBMQRadar.test_integration() took: {time.time() - start} seconds"
            )
            return data

        except Exception as e:
            logger.error(f"An error occurred in IBMQradar._get_tenants(): {str(e)}")
            return

    def _get_tenants(self):
        """
        Fetches the list of tenants from the IBM QRadar endpoint.

        This method sends an HTTP GET request to the IBM QRadar tenant management API endpoint
        to retrieve the list of tenants. It uses HTTP basic authentication with the credentials
        set in the IBMQradarConstants. If the request is successful, it returns the parsed JSON
        response. If the request fails or an exception occurs, it logs an error and returns an
        empty dictionary.

        :return: A dictionary containing tenant information if the request is successful, otherwise an empty dictionary.
        :raises: Logs any exceptions that occur during the request.
        """
        start = time.time()
        endpoint = f"{self.base_url}/{IBMQradarConstants.IBM_TENANT_ENDPOINT}"
        try:
            response = requests.get(
                endpoint,
                auth=HTTPBasicAuth(
                    self.username,
                    self.password,
                ),
                verify=SSLConstants.VERIFY,  # TODO : Handle this to TRUE in production
                timeout=SSLConstants.TIMEOUT,
            )
            if response.status_code != 200:
                logger.warning(
                    f"IBMQRadar._get_tenants() return the status code {response.status_code}"
                )
                return

            tenants = response.json()
            logger.success(
                f"IBMQRadar._get_tenants() took: {time.time() - start} seconds"
            )
            return tenants

        except Exception as e:
            logger.error(f"An error occurred in IBMQradar._get_tenants(): {str(e)}")

    def _get_domains(self):
        """
        Fetches the list of domains from the IBM QRadar endpoint.

        This method sends an HTTP GET request to the IBM QRadar domain management API endpoint
        to retrieve the list of domains. It uses HTTP basic authentication with the credentials
        set in the IBMQradarConstants. If the request is successful, it returns the parsed JSON
        response. If the request fails or an exception occurs, it logs an error and returns an
        empty dictionary.

        :return: A dictionary containing domain information if the request is successful, otherwise an empty dictionary.
        :raises: Logs any exceptions that occur during the request.
        """
        start = time.time()
        endpoint = f"{self.base_url}/{IBMQradarConstants.IBM_DOMAIN_ENDPOINT}"
        try:
            response = requests.get(
                endpoint,
                auth=HTTPBasicAuth(
                    self.username,
                    self.password,
                ),
                verify=SSLConstants.VERIFY,  # TODO : Handle this to TRUE in production
                timeout=SSLConstants.TIMEOUT,
            )
            if response.status_code != 200:
                logger.warning(
                    f"IBMQRadar._get_domains() return the status code {response.status_code}"
                )
                return

            domains = response.json()
            logger.success(
                f"IBMQRadar._get_domains() took: {time.time() - start} seconds"
            )
            return domains

        except Exception as e:
            logger.error(f"An error occurred in IBMQradar._get_domains(): {str(e)}")

    def _get_event_collectors(self):
        """
        Fetches the list of event collectors from the IBM QRadar endpoint.

        This method sends an HTTP GET request to the IBM QRadar event collector API endpoint
        to retrieve the list of event collectors. It uses HTTP basic authentication with the credentials
        set in the IBMQradarConstants. If the request is successful, it returns the parsed JSON
        response. If the request fails or an exception occurs, it logs an error and returns an
        empty dictionary.

        :return: A dictionary containing event collector information if the request is successful, otherwise an empty dictionary.
        :raises: Logs any exceptions that occur during the request.
        """
        start = time.time()
        endpoint = f"{self.base_url}/{IBMQradarConstants.IBM_EVENT_COLLECTOR_ENDPOINT}"
        try:
            response = requests.get(
                endpoint,
                auth=HTTPBasicAuth(
                    self.username,
                    self.password,
                ),
                verify=SSLConstants.VERIFY,  # TODO : Handle this to TRUE in production
                timeout=SSLConstants.TIMEOUT,
            )
            if response.status_code != 200:
                logger.warning(
                    f"IBMQRadar._get_event_collectors() return the status code {response.status_code}"
                )
                return

            event_collectors = response.json()
            logger.success(
                f"IBMQRadar._get_event_collectors() took: {time.time() - start} seconds"
            )
            return event_collectors

        except Exception as e:
            logger.error(
                f"An error occurred in IBMQradar._get_event_collectors(): {str(e)}"
            )

    def _get_log_sources_types(self):
        """
        Fetches the list of log source types from the IBM QRadar endpoint.

        This method sends an HTTP GET request to the IBM QRadar log source types API endpoint
        to retrieve the list of log source types. It uses HTTP basic authentication with the credentials
        set in the IBMQradarConstants. If the request is successful, it returns the parsed JSON
        response. If the request fails or an exception occurs, it logs an error and returns None.

        :return: A dictionary containing log source type information if the request is successful, otherwise None.
        :raises: Logs any exceptions that occur during the request.
        """

        start = time.time()
        endpoint = (
            f"{self.base_url}/{IBMQradarConstants.IBM_LOG_SOURCES_TYPES_ENDPOINT}"
        )
        try:
            response = requests.get(
                endpoint,
                auth=HTTPBasicAuth(
                    self.username,
                    self.password,
                ),
                verify=SSLConstants.VERIFY,  # TODO : Handle this to TRUE in production
                timeout=SSLConstants.TIMEOUT,
            )
            if response.status_code != 200:
                logger.warning(
                    f"IBMQRadar._get_log_sources_types() return the status code {response.status_code}"
                )
                return

            log_sources_types = response.json()
            logger.success(
                f"IBMQRadar._get_log_sources_types() took: {time.time() - start} seconds"
            )
            return log_sources_types

        except Exception as e:
            logger.error(
                f"An error occurred in IBMQradar._get_log_sources_types(): {str(e)}"
            )

    def _get_event_logs(self):
        """
        Fetches the list of event logs from the IBM QRadar endpoint.

        This method sends an HTTP GET request to the IBM QRadar event logs API endpoint
        to retrieve the list of event logs. It uses HTTP basic authentication with the credentials
        set in the IBMQradarConstants. If the request is successful, it returns the parsed JSON
        response. If the request fails or an exception occurs, it logs an error and returns an
        empty dictionary.

        :return: A dictionary containing event log information if the request is successful, otherwise an empty dictionary.
        :raises: Logs any exceptions that occur during the request.
        """
        start = time.time()
        endpoint = f"{self.base_url}/{IBMQradarConstants.IBM_EVENT_LOGS_ENDPOINT}"
        try:
            response = requests.get(
                endpoint,
                auth=HTTPBasicAuth(
                    self.username,
                    self.password,
                ),
                verify=SSLConstants.VERIFY,  # TODO : Handle this to TRUE in production
                timeout=SSLConstants.TIMEOUT,
            )
            if response.status_code != 200:
                logger.warning(
                    f"IBMQRadar._get_event_logs() return the status code {response.status_code}"
                )
                return
            logs = response.json()
            logger.success(
                f"IBMQRadar._get_event_logs() took: {time.time() - start} seconds"
            )
            return logs

        except Exception as e:
            logger.error(f"An error occurred in IBMQradar.__get_event_logs(): {str(e)}")

    def _transform_log_sources_types(self, log_sources_types, integration_id: int):
        """
        Transforms the list of log sources types fetched from the IBM QRadar endpoint into a pandas DataFrame,
        renames the columns to match the IBMQradarLogSourceTypes model, adds an integration_id column and
        converts it back to a list of dictionaries.

        :param log_sources_types: List of log sources types fetched from the IBM QRadar endpoint.
        :param integration_id: The ID of the integration that this data is associated with.
        :return: A list of dictionaries where each dictionary represents a log source type.
        """
        df = pd.DataFrame(data=log_sources_types)
        df = df[["id", "name", "version"]]
        df.rename(columns={"id": "db_id"}, inplace=True)
        df["integration_id"] = integration_id
        data = df.to_dict(orient="records")
        return data

    def _transform_domains(self, data, integration_id):
        """
        Transforms the list of domains from the IBM QRadar endpoint into a DataFrame, removes
        any rows with missing or empty names, renames the "id" column to "db_id", and returns
        the resulting DataFrame as a list of dictionaries.

        :param data: A list of dictionaries containing domain information.
        :return: A list of dictionaries containing the transformed domain information.
        """
        df = pd.DataFrame(data=data)
        df.rename(columns={"id": "db_id"}, inplace=True)
        df.dropna(subset=["name"], inplace=True)
        df = df[df["name"].str.strip() != ""]
        df = df[["db_id", "name"]]
        df["integration_id"] = integration_id
        data = df.to_dict(orient="records")

        return data

    def _insert_domains(self, data):
        """
        Inserts or updates domain records in the DuIbmQradarTenants table.

        :param data: A list of dictionaries containing domain information.
        """
        start = time.time()
        logger.info(f"IBMQRadar._insert_domains() started : {start}")
        records = [DuIbmQradarTenants(**item) for item in data]
        logger.info(f"Inserting the domains records: {len(records)}")
        try:
            with transaction.atomic():
                DuIbmQradarTenants.objects.bulk_create(
                    records,
                    update_conflicts=True,
                    update_fields=["name"],
                    unique_fields=["db_id"],
                )
                logger.info(f"Inserted the domains records: {len(records)}")
                logger.success(
                    f"IBMQRadar._insert_domains() took: {time.time() - start} seconds"
                )
        except Exception as e:
            logger.error(f"An error occurred in IBMQradar._insert_domains(): {str(e)}")
            transaction.rollback()

    def _transform_event_collectors(self, data, integration_id):
        """
        Transforms the list of event collectors from the IBM QRadar endpoint into a list of dictionaries.

        :param data: A list of dictionaries containing event collector information.
        :return: A list of dictionaries containing the transformed event collector information.
        """
        df = pd.DataFrame(data=data)
        df = df[["id", "name", "host_id", "component_name"]]
        df.dropna(subset=["id", "name"], inplace=True)
        df = df[df["name"].str.strip() != ""]
        df.rename(columns={"id": "db_id"}, inplace=True)
        df["integration_id"] = integration_id
        return df.to_dict(orient="records")

    def _insert_event_collectors(self, data):
        """
        Inserts or updates event collector records in the IBMQradarEventCollector table.

        :param data: A list of dictionaries containing event collector information.
        """
        start = time.time()
        logger.info(f"IBMQRadar._insert_event_collectors() started: {start}")
        records = [IBMQradarEventCollector(**item) for item in data]
        logger.info(f"Inserting event collector records: {len(records)}")
        try:
            with transaction.atomic():
                IBMQradarEventCollector.objects.bulk_create(
                    records,
                    update_conflicts=True,
                    update_fields=["name", "host_id", "component_name"],
                    unique_fields=["db_id"],
                )
            logger.info(f"Inserted event collector records: {len(records)}")
            logger.success(
                f"IBMQRadar._insert_event_collectors() took: {time.time() - start} seconds"
            )
        except Exception as e:
            logger.error(
                f"An error occurred in IBMQradar._insert_event_collectors(): {str(e)}"
            )
            transaction.rollback()

    def _transform_event_logs(self, data, integration_id):
        """
        Transforms the list of event logs from the IBM QRadar endpoint into a DataFrame, removes
        any rows with missing or empty names, renames the "id" column to "db_id", and returns
        the resulting DataFrame as a list of dictionaries.

        :param data: A list of dictionaries containing event log information.
        :return: A list of dictionaries containing the transformed event log information.
        """
        collector_map = DBMappings.get_db_id_to_id_mapping(IBMQradarEventCollector)
        log_sources_types_map = DBMappings.get_db_id_to_id_mapping(
            IBMQradarLogSourceTypes
        )

        df = pd.DataFrame(data=data)
        df["integration_id"] = integration_id
        df["status_value"] = df["status"].apply(
            lambda x: x.get("status") if isinstance(x, dict) else None
        )

        df = df[
            [
                "id",
                "name",
                "description",
                "sending_ip",
                "enabled",
                "status_value",
                "average_eps",
                "target_event_collector_id",
                "creation_date",
                "type_id",
                "modified_date",
                "last_event_time",
                "integration_id",
            ]
        ]
        df.rename(columns={"id": "db_id", "status_value": "status"}, inplace=True)
        df.dropna(subset=["target_event_collector_id"], inplace=True)
        df["event_collector_id"] = df["target_event_collector_id"].map(collector_map)
        df["log_source_type_id"] = df["type_id"].map(log_sources_types_map)
        df.drop(columns=["type_id"], inplace=True)
        data = df.to_dict(orient="records")

        return data

    def _insert_event_logs(self, data):
        """
        Inserts or updates event log records in the IBMQradarEventLog table.

        :param data: A list of dictionaries containing event log information.
        """
        start = time.time()
        logger.info(f"IBMQRadar._insert_event_logs() started: {start}")
        records = [IBMQradarAssests(**item) for item in data]
        logger.info(f"Inserting event log records: {len(records)}")
        try:
            with transaction.atomic():
                IBMQradarAssests.objects.bulk_create(
                    records,
                    update_conflicts=True,
                    update_fields=[
                        "name",
                        "description",
                        "average_eps",
                        "event_collector_id",
                        "log_source_type_id",
                        "sending_ip",
                        "enabled",
                        "status",
                        "creation_date",
                        "modified_date",
                        "last_event_time",
                    ],
                    unique_fields=["db_id"],
                )
            logger.info(f"Inserted event log records: {len(records)}")
            logger.success(
                f"IBMQRadar._insert_event_logs() took: {time.time() - start} seconds"
            )
        except Exception as e:
            logger.error(
                f"An error occurred in IBMQradar._insert_event_logs(): {str(e)}"
            )
            transaction.rollback()

    def _get_offenses(self):
        """
        Fetches the list of offenses from the IBM QRadar endpoint.

        This method sends an HTTP GET request to the IBM QRadar offenses API endpoint
        to retrieve the list of offenses. It uses HTTP basic authentication with the credentials
        set in the IBMQradarConstants. If the request is successful, it returns the parsed JSON
        response. If the request fails or an exception occurs, it logs an error and returns an
        empty dictionary.

        :return: A dictionary containing offense information if the request is successful, otherwise an empty dictionary.
        :raises: Logs any exceptions that occur during the request.
        """
        start = time.time()
        logger.info(f"IBMQRadar._get_offenses() started: {start}")
        endpoint = f"{self.base_url}/{IBMQradarConstants.IBM_OFFENSES_ENDPOINT}"
        try:
            response = requests.get(
                endpoint,
                auth=HTTPBasicAuth(
                    self.username,
                    self.password,
                ),
                verify=SSLConstants.VERIFY,  # TODO : Handle this to TRUE in production
                timeout=SSLConstants.TIMEOUT,
            )
            if response.status_code != 200:
                logger.warning(
                    f"IBMQRadar._get_offenses() return the status code {response.status_code}"
                )
                return
            response = response.json()
            logger.success(
                f"IBMQRadar._get_offenses() took: {time.time() - start} seconds"
            )
            return response
        except Exception as e:
            logger.error(f"An error occurred in IBMQradar._get_offenses(): {str(e)}")

    def _transform_offenses(self, data, integration_id):
        """
        Transforms the list of offenses from the IBM QRadar endpoint into a list of IBMQradarOffense instances
        suitable for insertion into the database.

        :param data: A list of dictionaries containing offense information.
        :param integration_id: The ID of the integration associated with the data.
        :return: A tuple containing a list of (IBMQradarOffense instance, assest_ids) tuples and a dictionary mapping asset db_id to id.
        """
        start = time.time()
        logger.info(f"IBMQRadar._transform_offenses() started: {start}")

        if not data:
            logger.warning("No offense data found for QRadar")
            return [], {}

        records = []
        tenant_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
        asset_map = DBMappings.get_db_id_to_id_mapping(IBMQradarAssests)

        for entry in data:
            domain_id = entry.get("domain_id")
            if domain_id is None or domain_id == "" or domain_id == " ":
                logger.warning(
                    f"Skipping offense with invalid domain_id: {entry.get('id')}"
                )
                continue

            # Map domain_id to tenant_id (primary key of DuIbmQradarTenants)
            tenant_id = tenant_map.get(domain_id)
            if tenant_id is None:
                logger.warning(
                    f"Skipping offense with db_id {entry.get('id')} due to missing tenant with domain_id {domain_id}"
                )
                continue

            # Extract log_sources IDs for many-to-many relationship
            log_sources = entry.get("log_sources", [])
            assest_ids = [
                asset_map.get(ls["id"])
                for ls in log_sources
                if ls.get("id") in asset_map
            ]

            record = IBMQradarOffense(
                db_id=entry.get("id"),
                qradar_tenant_domain_id=tenant_id,
                description=entry.get("description"),
                event_count=entry.get("event_count", 0),
                flow_count=entry.get("flow_count", 0),
                assigned_to=entry.get("assigned_to"),
                integration_id=integration_id,
                security_category_count=entry.get("security_category_count", 0),
                follow_up=entry.get("follow_up", False),
                source_address_ids=entry.get("source_address_ids", []),
                source_count=entry.get("source_count", 0),
                inactive=entry.get("inactive", False),
                protected=entry.get("protected", False),
                closing_user=entry.get("closing_user"),
                destination_networks=entry.get("destination_networks", []),
                source_network=entry.get("source_network"),
                category_count=entry.get("category_count", 0),
                close_time=entry.get("close_time"),
                remote_destination_count=entry.get("remote_destination_count", 0),
                start_time=entry.get("start_time"),
                magnitude=entry.get("magnitude", 0),
                last_updated_time=entry.get("last_updated_time"),
                last_persisted_time=entry.get("last_persisted_time"),
                first_persisted_time=entry.get("first_persisted_time"),
                credibility=entry.get("credibility", 0),
                severity=entry.get("severity", 0),
                policy_category_count=entry.get("policy_category_count", 0),
                closing_reason_id=entry.get("closing_reason_id"),
                device_count=entry.get("device_count", 0),
                offense_type=entry.get("offense_type", 0),
                relevance=entry.get("relevance", 0),
                offense_source=entry.get("offense_source"),
                local_destination_address_ids=entry.get(
                    "local_destination_address_ids", []
                ),
                local_destination_count=entry.get("local_destination_count", 0),
                status=entry.get("status"),
                categories=entry.get("categories", []),
                rules=entry.get("rules", []),
            )
            records.append((record, assest_ids))

        logger.success(
            f"IBMQRadar._transform_offenses() took: {time.time() - start} seconds, transformed {len(records)} offenses"
        )
        return records, asset_map

    def _insert_offenses(self, transformed_data):
        """
        Inserts or updates offense records in the IBMQradarOffense table and sets their assests relationships.

        :param transformed_data: A list of tuples containing IBMQradarOffense instances and their assest_ids.
        """
        start = time.time()
        logger.info(f"IBMQRadar._insert_offenses() started: {start}")

        try:
            records = [record for record, _ in transformed_data]
            assest_mappings = [
                (record.db_id, assest_ids) for record, assest_ids in transformed_data
            ]

            logger.info(f"Inserting offense records: {len(records)}")

            with transaction.atomic():
                # Bulk create or update offenses
                IBMQradarOffense.objects.bulk_create(
                    records,
                    update_conflicts=True,
                    update_fields=[
                        "qradar_tenant_domain",
                        "description",
                        "event_count",
                        "flow_count",
                        "assigned_to",
                        "security_category_count",
                        "follow_up",
                        "source_address_ids",
                        "source_count",
                        "inactive",
                        "protected",
                        "closing_user",
                        "destination_networks",
                        "source_network",
                        "category_count",
                        "close_time",
                        "remote_destination_count",
                        "start_time",
                        "magnitude",
                        "last_updated_time",
                        "last_persisted_time",
                        "first_persisted_time",
                        "credibility",
                        "severity",
                        "policy_category_count",
                        "closing_reason_id",
                        "device_count",
                        "offense_type",
                        "relevance",
                        "offense_source",
                        "local_destination_address_ids",
                        "local_destination_count",
                        "status",
                        "categories",
                        "rules",
                    ],
                    unique_fields=["db_id"],
                )

                # Set many-to-many relationships for assests
                for db_id, assest_ids in assest_mappings:
                    offense = IBMQradarOffense.objects.get(db_id=db_id)
                    if assest_ids:
                        offense.assests.set(assest_ids)
                    else:
                        logger.warning(
                            f"No valid assets found for offense db_id: {db_id}"
                        )

            logger.info(f"Inserted/updated offense records: {len(records)}")
            logger.success(
                f"IBMQRadar._insert_offenses() took: {time.time() - start} seconds"
            )

        except Exception as e:
            logger.error(f"An error occurred in IBMQradar._insert_offenses(): {str(e)}")
            transaction.rollback()

    def _insert_log_sources_types(self, data):
        """
        Inserts or updates log source types in the IBMQradarLogSourceTypes table.

        :param data: A list of dictionaries containing log source type information.
        """
        start = time.time()
        logger.info(f"IBMQRadar._insert_log_sources_types() started : {start}")
        records = [IBMQradarLogSourceTypes(**item) for item in data]
        logger.info(f"Inserting the log sources types records: {len(records)}")
        try:
            with transaction.atomic():
                IBMQradarLogSourceTypes.objects.bulk_create(
                    records,
                    update_conflicts=True,
                    update_fields=["name", "version"],
                    unique_fields=["db_id"],
                )
                logger.info(f"Inserted the domains records: {len(records)}")
                logger.success(
                    f"IBMQRadar._insert_log_sources_types() took: {time.time() - start} seconds"
                )
        except Exception as e:
            logger.error(
                f"An error occurred in IBMQradar._insert_log_sources_types(): {str(e)}"
            )
            transaction.rollback()

    def _get_eps_domain(self, domain_id: int):
        """
        Execute an AQL query to get the EPS by domain ID.

        The query will be executed against the IBM QRadar API and the results will be
        returned as a search ID which can be used to retrieve the results.

        :param domain_id: The domain ID to query.
        :return: The search ID which can be used to retrieve the results.
        """
        AQL_QUERY = f'SELECT "domainid", logsourceid, COUNT(*) / 300 AS eps FROM events WHERE starttime > NOW() - 300000 AND "domainid" = {domain_id} GROUP BY "domainid", logsourceid ORDER BY eps DESC'  # nosec
        endpoint = f"{self.base_url}/{IBMQradarConstants.IBM_EPS_ENDPOINT}"
        try:
            response = requests.post(
                endpoint,
                auth=HTTPBasicAuth(
                    self.username,
                    self.password,
                ),
                data={"query_expression": AQL_QUERY},
                verify=SSLConstants.VERIFY,  # TODO : Handle this to TRUE in production
                timeout=SSLConstants.TIMEOUT,
            )
        except Exception as e:
            logger.error(f"An error occurred in IBMQRadar._get_eps_domain(): {str(e)}")
            return

        if response.status_code not in [200, 201]:
            logger.warning(
                f"IBMQRadar._get_eps_domain() return the status code {response.status_code}"
            )
            return

        search_id = response.json().get("search_id")
        return search_id

    def _get_do_aql_query(self, query: str):
        """
        Execute an AQL query to get the EPS by domain ID.

        The query will be executed against the IBM QRadar API and the results will be
        returned as a search ID which can be used to retrieve the results.

        :param domain_id: The domain ID to query.
        :return: The search ID which can be used to retrieve the results.
        """
        endpoint = f"{self.base_url}/{IBMQradarConstants.IBM_EPS_ENDPOINT}"
        try:
            response = requests.post(
                endpoint,
                auth=HTTPBasicAuth(
                    self.username,
                    self.password,
                ),
                data={"query_expression": query},
                verify=SSLConstants.VERIFY,  # TODO : Handle this to TRUE in production
                timeout=SSLConstants.TIMEOUT,
            )
        except Exception as e:
            logger.error(f"An error occurred in IBMQRadar._get_eps_domain(): {str(e)}")
            return

        if response.status_code not in [200, 201]:
            logger.warning(
                f"IBMQRadar._get_eps_domain() return the status code {response.status_code}"
            )
            return

        search_id = response.json().get("search_id")
        return search_id

    def _check_eps_results_by_search_id(self, search_id: int):
        """
        Returns the results for a given search ID.

        :param search_id: The ID of the search.
        :return: The results.
        """
        while True:
            endpoint = (
                f"{self.base_url}/{IBMQradarConstants.IBM_EPS_ENDPOINT}/{search_id}"
            )
            try:
                response = requests.get(
                    endpoint,
                    auth=HTTPBasicAuth(
                        self.username,
                        self.password,
                    ),
                    verify=SSLConstants.VERIFY,  # TODO : Handle this to TRUE in production
                    timeout=SSLConstants.TIMEOUT,
                )
            except Exception as e:
                logger.error(
                    f"An error occurred in IBMQRadar._check_eps_results_by_search_id(): {str(e)}"
                )
                return

            if response.status_code != 200:
                logger.warning(
                    f"IBMQRadar._check_eps_results_by_search_id() return the status code {response.status_code}"
                )
                return

            status = response.json().get("status")

            if status == "COMPLETED":
                break
            elif status in ["ERROR", "CANCELLED"]:
                logger.info(
                    f"IBMQRadar._check_eps_results_by_search_id() status: {status}"
                )

            time.sleep(2)
        return True

    def _get_eps_results_by_search_id(self, search_id: int):
        """
        Returns the results for a given search ID.

        :param search_id: The ID of the search.
        :return: The results.
        """
        endpoint = (
            f"{self.base_url}/{IBMQradarConstants.IBM_EPS_ENDPOINT}/{search_id}/results"
        )
        try:
            response = requests.get(
                endpoint,
                auth=HTTPBasicAuth(
                    self.username,
                    self.password,
                ),
                verify=SSLConstants.VERIFY,  # TODO : Handle this to TRUE in production
                timeout=SSLConstants.TIMEOUT,
            )
        except Exception as e:
            logger.error(
                f"An error occurred in IBMQRadar._get_eps_results_by_search_id(): {str(e)}"
            )
        if response.status_code != 200:
            logger.warning(
                f"IBMQRadar._get_eps_results_by_search_id() return the status code {response.status_code}"
            )
            return
        results = response.json().get("events", [])
        return results

    def _transform_eps_data(self, data_list, integration):
        """
        Transforms the list of eps data from the IBM QRadar endpoint into a list of IBMQradarEPS objects.

        :param data_list: A list of dictionaries containing eps data.
        :param integration: The integration object associated with the data.
        :return: A list of IBMQradarEPS objects.
        """
        domain_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
        log_source_map = DBMappings.get_db_id_to_id_mapping(IBMQradarAssests)
        eps_objects = []
        for data in data_list:
            domain = domain_map.get(data["domainid"])
            log_source = log_source_map.get(data["logsourceid"])
            if domain is None or log_source is None:
                logger.warning(
                    f"Skipping eps with invalid domain or log_source: {data.get('id')}"
                )
                continue
            try:
                eps_obj = IBMQradarEPS(
                    domain_id=domain,
                    log_source_id=log_source,
                    eps=data["eps"],
                    integration_id=integration,
                )
                eps_objects.append(eps_obj)
            except Exception as e:
                logger.error(
                    f"An error occurred in IBMQRadar._transform_eps_data(): {str(e)}"
                )
        return eps_objects

    def _insert_eps(self, data):
        """
        Inserts or updates EPS records in the IBMQradarEPS table.

        :param data: A list of IBMQradarEPS objects.
        """
        start = time.time()
        logger.info(f"IBMQRadar._insert_eps() started : {start}")
        try:
            with transaction.atomic():
                IBMQradarEPS.objects.bulk_create(
                    data,
                )
        except Exception as e:
            logger.error(f"An error occurred in IBMQradar._insert_eps(): {str(e)}")
            transaction.rollback()

    def _transform_customer_eps_data(self, data_list, integration):
        """
        Transforms raw EPS data into CustomerEPS model-ready dicts.

        :param data_list: List of dicts with 'Customer' and 'EPS'
        :param integration: Integration instance
        :return: List of dictionaries for CustomerEPS model creation
        """
        name_to_id_map = DBMappings.get_name_to_id_mapping(DuIbmQradarTenants)
        transformed = []

        for entry in data_list:
            customer = entry.get("Customer")
            eps = entry.get("EPS")

            if not customer or eps is None:
                logger.warning(f"Skipping invalid EPS data: {entry}")
                continue

            tenant_id = name_to_id_map.get(customer)
            if not tenant_id:
                logger.warning(
                    f"No matching QRadar tenant found for customer: {customer}"
                )
                continue
            try:
                eps = float(eps)
            except ValueError:
                logger.warning(f"Invalid EPS value: {eps}")
                continue
            transformed.append(
                {
                    "customer": customer.strip(),
                    "eps": eps,
                    "qradar_tenant_id": tenant_id,
                    "integration_id": integration,
                }
            )

        return transformed

    def _insert_customer_eps(self, data):
        """
        Inserts or updates CustomerEPS records in bulk.

        :param data: A list of dictionaries (transformed EPS data)
        """
        start = time.time()
        logger.info(f"IBMQRadar._insert_customer_eps() started : {start}")

        records = [CustomerEPS(**item) for item in data]
        logger.info(f"Inserting CustomerEPS records: {len(records)}")

        try:
            with transaction.atomic():
                CustomerEPS.objects.bulk_create(
                    records,
                )
                logger.success(f"Inserted CustomerEPS records: {len(records)}")
                logger.success(
                    f"IBMQRadar._insert_customer_eps() took: {time.time() - start:.2f} seconds"
                )
        except Exception as e:
            logger.error(f"Error in IBMQRadar._insert_customer_eps(): {str(e)}")
            transaction.rollback()

    def _transform_total_events_data(self, data, integration, domain_id):
        """
        Transforms raw total events data into TotalEvents model-ready dicts.

        :param data: Dict with 'total_events' (e.g., {'total_events': 542657416.0})
        :param integration: Integration ID
        :param domain_id: QRadar domain ID
        :return: Dictionary for TotalEvents model creation
        """
        if not data:
            logger.warning(f"Invalid total events data: {data}")
            return None
        total_events = data.get("total_events")
        if total_events is None:
            logger.warning(f"Invalid total events data for domain {domain_id}: {data}")
            return None

        mappings = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
        tenant_id = mappings.get(domain_id)
        if not tenant_id:
            logger.warning(f"No matching QRadar tenant found for domain: {domain_id}")
            return None

        return {
            "total_events": total_events,
            "qradar_tenant_id": tenant_id,
            "integration_id": integration,
        }

    def _insert_total_events(self, data_list):
        """
        Inserts or updates TotalEvents records in bulk.

        :param data_list: List of dictionaries (transformed total events data)
        """
        start = time.time()
        logger.info(f"IBMQRadar._insert_total_events() started: {start}")

        records = [TotalEvents(**item) for item in data_list if item]
        logger.info(f"Inserting TotalEvents records: {len(records)}")

        try:
            with transaction.atomic():
                TotalEvents.objects.bulk_create(
                    records,
                    update_conflicts=True,
                    update_fields=[
                        "total_events",
                        "qradar_tenant_id",
                        "integration_id",
                    ],
                    unique_fields=["domain_id", "integration_id"],
                )
                logger.info(f"Inserted TotalEvents records: {len(records)}")
                logger.info(
                    f"IBMQRadar._insert_total_events() took: {time.time() - start:.2f} seconds"
                )
        except Exception as e:
            logger.error(f"Error in IBMQRadar._insert_total_events(): {str(e)}")
            transaction.rollback()

    def _transform_event_count_data(self, data_list, integration_id, domain_id):
        name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
        tenant_id = name_to_id_map.get(domain_id)
        transformed = []

        for entry in data_list:
            event_name = entry.get("event_name")
            event_count = entry.get("event_count")

            if not event_name or event_count is None:
                logger.warning(f"Skipping invalid event data: {entry}")
                continue

            if not tenant_id:
                logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
                continue

            transformed.append(
                {
                    "event_name": event_name.strip(),
                    "event_count": event_count,
                    "qradar_tenant_id": tenant_id,
                    "integration_id": integration_id,
                }
            )

        return transformed

    def _insert_event_count_data(self, data):
        logger.info(f"Inserting {len(data)} EventCountLog records")
        records = [EventCountLog(**item) for item in data]

        try:
            with transaction.atomic():
                EventCountLog.objects.bulk_create(records)
                logger.success(f"Inserted EventCountLog records: {len(records)}")
        except Exception as e:
            logger.error(f"Error inserting EventCountLog records: {str(e)}")
            transaction.rollback()

    # def _transform_recon_data(self, data_list, integration_id, domain_id):
    #     name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
    #     tenant_id = name_to_id_map.get(domain_id)

    #     if not tenant_id:
    #         logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
    #         return []

    #     for entry in data_list:
    #         count = entry.get("total_recon_events")
    #         if count is None:
    #             logger.warning(f"Skipping invalid recon data: {entry}")
    #             continue

    #         return [
    #             {
    #                 "total_recon_events": count,
    #                 "integration_id": integration_id,
    #                 "qradar_tenant_id": tenant_id,
    #             }
    #         ]

    #     return []
    def _transform_recon_data(self, data_list, integration_id, domain_id, date=None):
        name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
        tenant_id = name_to_id_map.get(domain_id)

        if not tenant_id:
            logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
            return []

        for entry in data_list:
            count = entry.get("total_recon_events")
            if count is None:
                logger.warning(f"Skipping invalid recon data: {entry}")
                continue

            if date is None:
                return [
                    {
                        "total_recon_events": count,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                    }
                ]
            else:
                return [
                    {
                        "total_recon_events": count,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                        "created_at": date,
                    }
                ]

        return []

    def _insert_recon_event_data(self, data):
        logger.info(f"Inserting {len(data)} ReconEventLog records")
        records = [ReconEventLog(**item) for item in data]

        try:
            with transaction.atomic():
                ReconEventLog.objects.bulk_create(records)
                logger.success(f"Inserted ReconEventLog records: {len(records)}")
        except Exception as e:
            logger.error(f"Error inserting ReconEventLog records: {str(e)}")
            transaction.rollback()

    def _transform_correlated_data(self, data_list, integration_id, domain_id):
        """Transform correlated events data for database insertion"""
        try:
            logger.info(f"Starting transformation for domain {domain_id}")
            logger.info(f"Input data: {data_list}")
            logger.info(f"Integration ID: {integration_id}")

            # Get tenant mapping
            name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
            logger.info(f"Available tenant mappings: {name_to_id_map}")

            tenant_id = name_to_id_map.get(domain_id)
            logger.info(f"Tenant ID for domain {domain_id}: {tenant_id}")

            if not tenant_id:
                logger.error(f"No QRadar tenant found for domain_id: {domain_id}")
                logger.error(f"Available domain_ids: {list(name_to_id_map.keys())}")
                return []

            if not data_list:
                logger.warning("No data received from QRadar")
                return []

            # Process each entry in the data list
            transformed_data = []
            for i, entry in enumerate(data_list):
                logger.info(f"Processing entry {i+1}/{len(data_list)}: {entry}")

                # Handle different possible response formats
                count = None
                if isinstance(entry, dict):
                    count = entry.get("correlated_events_count")
                    if count is None:
                        # Try alternative field names
                        count = entry.get("count")
                        if count is None:
                            # Try to get the first numeric value
                            for key, value in entry.items():
                                if isinstance(value, (int, float)):
                                    count = value
                                    logger.info(
                                        f"Using value {count} from field '{key}'"
                                    )
                                    break
                elif isinstance(entry, (int, float)):
                    count = entry
                    logger.info(f"Direct numeric value: {count}")

                if count is None:
                    logger.warning(f"Could not extract count from entry: {entry}")
                    continue

                # Convert to float and validate
                try:
                    count = float(count)
                    if count < 0:
                        logger.warning(f"Negative count value: {count}, setting to 0")
                        count = 0
                except (ValueError, TypeError):
                    logger.warning(f"Invalid count value: {count}, skipping entry")
                    continue

                transformed_entry = {
                    "correlated_events_count": count,
                    "integration_id": integration_id,
                    "qradar_tenant_id": tenant_id,
                }

                transformed_data.append(transformed_entry)
                logger.info(f"Successfully transformed entry: {transformed_entry}")

            logger.info(
                f"Transformation complete: {len(transformed_data)} records created"
            )
            return transformed_data

        except Exception as e:
            logger.error(
                f"Error in _transform_correlated_data: {str(e)}", exc_info=True
            )
            return []

    def _insert_correlated_event_data(self, data):
        """Insert correlated event data into database"""
        try:
            logger.info(f"Starting insertion of {len(data)} CorrelatedEventLog records")
            logger.info(f"Data to insert: {data}")

            if not data:
                logger.warning("No data to insert")
                return False

            # Validate data structure
            for i, item in enumerate(data):
                required_fields = [
                    "correlated_events_count",
                    "integration_id",
                    "qradar_tenant_id",
                ]
                for field in required_fields:
                    if field not in item:
                        logger.error(
                            f"Missing required field '{field}' in item {i}: {item}"
                        )
                        return False

            # Create records
            records = []
            for item in data:
                try:
                    record = CorrelatedEventLog(
                        correlated_events_count=item["correlated_events_count"],
                        integration_id=item["integration_id"],
                        qradar_tenant_id=item["qradar_tenant_id"],
                    )
                    records.append(record)
                    logger.debug(f"Created record: {record}")
                except Exception as e:
                    logger.error(f"Error creating record from item {item}: {str(e)}")
                    return False

            # Bulk insert with transaction
            try:
                with transaction.atomic():
                    created_records = CorrelatedEventLog.objects.bulk_create(records)
                    logger.info(
                        f"Successfully inserted {len(created_records)} CorrelatedEventLog records"
                    )

                    # Verify insertion
                    total_count = CorrelatedEventLog.objects.count()
                    logger.info(
                        f"Total CorrelatedEventLog records in database: {total_count}"
                    )

                    return True

            except Exception as e:
                logger.error(
                    f"Database error during bulk_create: {str(e)}", exc_info=True
                )
                return False

        except Exception as e:
            logger.error(
                f"Error in _insert_correlated_event_data: {str(e)}", exc_info=True
            )
            return False

    def _transform_weekly_correlated_data(self, data_list, integration_id, domain_id):
        """Transform weekly correlated events data for database insertion"""
        try:
            logger.info(f"Starting weekly transformation for domain {domain_id}")
            logger.info(f"Input weekly data: {data_list}")
            logger.info(f"Integration ID: {integration_id}")

            # Get tenant mapping
            name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
            logger.info(f"Available tenant mappings: {name_to_id_map}")

            tenant_id = name_to_id_map.get(domain_id)
            logger.info(f"Tenant ID for domain {domain_id}: {tenant_id}")

            if not tenant_id:
                logger.error(f"No QRadar tenant found for domain_id: {domain_id}")
                logger.error(f"Available domain_ids: {list(name_to_id_map.keys())}")
                return []

            if not data_list:
                logger.warning("No weekly data received from QRadar")
                return []

            # Process each entry in the data list
            transformed_data = []
            for i, entry in enumerate(data_list):
                logger.info(f"Processing weekly entry {i+1}/{len(data_list)}: {entry}")

                if not isinstance(entry, dict):
                    logger.warning(f"Expected dict but got {type(entry)}: {entry}")
                    continue

                # Extract week and count
                week = entry.get("week")
                weekly_count = entry.get("weekly_count")

                # Validate week format
                if not week:
                    logger.warning(f"Missing week in entry: {entry}")
                    continue

                # Validate week format (should be yyyy-ww)
                if not isinstance(week, str) or len(week) != 7 or "-" not in week:
                    logger.warning(f"Invalid week format: {week}")
                    continue

                # Validate and convert count
                if weekly_count is None:
                    logger.warning(f"Missing weekly_count in entry: {entry}")
                    continue

                try:
                    weekly_count = float(weekly_count)
                    if weekly_count < 0:
                        logger.warning(
                            f"Negative weekly count: {weekly_count}, setting to 0"
                        )
                        weekly_count = 0
                except (ValueError, TypeError):
                    logger.warning(
                        f"Invalid weekly_count value: {weekly_count}, skipping entry"
                    )
                    continue

                transformed_entry = {
                    "week": week,
                    "weekly_count": weekly_count,
                    "integration_id": integration_id,
                    "qradar_tenant_id": tenant_id,
                }

                transformed_data.append(transformed_entry)
                logger.info(
                    f"Successfully transformed weekly entry: {transformed_entry}"
                )

            logger.info(
                f"Weekly transformation complete: {len(transformed_data)} records created"
            )
            return transformed_data

        except Exception as e:
            logger.error(
                f"Error in _transform_weekly_correlated_data: {str(e)}", exc_info=True
            )
            return []

    def _insert_weekly_correlated_event_data(self, data):
        """Insert weekly correlated event data into database"""
        try:
            logger.info(
                f"Starting insertion of {len(data)} WeeklyCorrelatedEventLog records"
            )
            logger.info(f"Weekly data to insert: {data}")

            if not data:
                logger.warning("No weekly data to insert")
                return False

            # Validate data structure
            for i, item in enumerate(data):
                required_fields = [
                    "week",
                    "weekly_count",
                    "integration_id",
                    "qradar_tenant_id",
                ]
                for field in required_fields:
                    if field not in item:
                        logger.error(
                            f"Missing required field '{field}' in weekly item {i}: {item}"
                        )
                        return False

            # Create records
            records = []
            for item in data:
                try:
                    record = WeeklyCorrelatedEventLog(
                        week=item["week"],
                        weekly_count=item["weekly_count"],
                        integration_id=item["integration_id"],
                        qradar_tenant_id=item["qradar_tenant_id"],
                    )
                    records.append(record)
                    logger.debug(f"Created weekly record: {record}")
                except Exception as e:
                    logger.error(
                        f"Error creating weekly record from item {item}: {str(e)}"
                    )
                    return False

            # Bulk insert with transaction
            try:
                with transaction.atomic():
                    # Use bulk_create with update_conflicts for handling duplicates
                    created_records = WeeklyCorrelatedEventLog.objects.bulk_create(
                        records,
                        update_conflicts=True,
                        update_fields=["weekly_count", "created_at"],
                        unique_fields=["integration", "qradar_tenant", "week"],
                    )
                    logger.info(
                        f"Successfully inserted/updated {len(created_records)} WeeklyCorrelatedEventLog records"
                    )

                    # Verify insertion
                    total_count = WeeklyCorrelatedEventLog.objects.count()
                    logger.info(
                        f"Total WeeklyCorrelatedEventLog records in database: {total_count}"
                    )

                    return True

            except Exception as e:
                logger.error(
                    f"Database error during weekly bulk_create: {str(e)}", exc_info=True
                )

                # Fallback: Insert one by one with get_or_create
                logger.info("Attempting fallback insertion method...")
                success_count = 0
                for item in data:
                    try:
                        (
                            record,
                            created,
                        ) = WeeklyCorrelatedEventLog.objects.get_or_create(
                            integration_id=item["integration_id"],
                            qradar_tenant_id=item["qradar_tenant_id"],
                            week=item["week"],
                            defaults={"weekly_count": item["weekly_count"]},
                        )
                        if not created:
                            # Update existing record
                            record.weekly_count = item["weekly_count"]
                            record.save()
                            logger.info(
                                f"Updated existing weekly record for week {item['week']}"
                            )
                        else:
                            logger.info(
                                f"Created new weekly record for week {item['week']}"
                            )
                        success_count += 1
                    except Exception as e:
                        logger.error(
                            f"Error in fallback insertion for item {item}: {str(e)}"
                        )

                logger.info(
                    f"Fallback insertion completed: {success_count}/{len(data)} records processed"
                )
                return success_count > 0

        except Exception as e:
            logger.error(
                f"Error in _insert_weekly_correlated_event_data: {str(e)}",
                exc_info=True,
            )
            return False

    # def _transform_suspicious_data(self, data_list, integration_id, domain_id):
    #     name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
    #     tenant_id = name_to_id_map.get(domain_id)

    #     if not tenant_id:
    #         logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
    #         return []

    #     for entry in data_list:
    #         count = entry.get("total_suspicious_events")
    #         if count is None:
    #             logger.warning(f"Skipping invalid suspicious data: {entry}")
    #             continue

    #         return [
    #             {
    #                 "total_suspicious_events": count,
    #                 "integration_id": integration_id,
    #                 "qradar_tenant_id": tenant_id,
    #             }
    #         ]

    #     return []
    def _transform_suspicious_data(self, data_list, integration_id, domain_id, date=None):
        name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
        tenant_id = name_to_id_map.get(domain_id)

        if not tenant_id:
            logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
            return []

        for entry in data_list:
            count = entry.get("total_suspicious_events")
            if count is None:
                logger.warning(f"Skipping invalid suspicious data: {entry}")
                continue

            if date is None:
                return [
                    {
                        "total_suspicious_events": count,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                    }
                ]
            else:
                return [
                    {
                        "total_suspicious_events": count,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                        "created_at": date,
                    }
                ]

        return []

    def _insert_suspicious_event_data(self, data):
        logger.info(f"Inserting {len(data)} SuspiciousEventLog records")
        records = [SuspiciousEventLog(**item) for item in data]

        try:
            with transaction.atomic():
                SuspiciousEventLog.objects.bulk_create(records)
                logger.success(f"Inserted SuspiciousEventLog records: {len(records)}")
        except Exception as e:
            logger.error(f"Error inserting SuspiciousEventLog records: {str(e)}")
            transaction.rollback()

    # TODO: Consider this example for DoS
    def _transform_dos_data(self, data_list, integration_id, domain_id, date=None):
        name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
        tenant_id = name_to_id_map.get(domain_id)

        if not tenant_id:
            logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
            return []

        for entry in data_list:
            count = entry.get("total_dos_events")
            if count is None:
                logger.warning(f"Skipping invalid DoS data: {entry}")
                continue

            if date is None:
                return [
                    {
                        "total_dos_events": count,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                    }
                ]
            else:
                return [
                    {
                        "total_dos_events": count,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                        "created_at": date,
                    }
                ]

        return []

    def _insert_dos_event_data(self, data):
        logger.info(f"Inserting {len(data)} DosEventLog records")
        records = [DosEventLog(**item) for item in data]

        try:
            with transaction.atomic():
                DosEventLog.objects.bulk_create(records)
                logger.success(f"Inserted DosEventLog records: {len(records)}")
        except Exception as e:
            logger.error(f"Error inserting DosEventLog records: {str(e)}")
            transaction.rollback()

    # def _transform_top_dos_data(self, data_list, integration_id, domain_id):
    #     name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
    #     tenant_id = name_to_id_map.get(domain_id)

    #     if not tenant_id:
    #         logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
    #         return []

    #     transformed = []
    #     for entry in data_list:
    #         event_name = entry.get("event_name")
    #         event_count = entry.get("event_count")
    #         if event_name is None or event_count is None:
    #             logger.warning(f"Skipping invalid top DoS data: {entry}")
    #             continue

    #         transformed.append(
    #             {
    #                 "event_name": event_name,
    #                 "event_count": event_count,
    #                 "integration_id": integration_id,
    #                 "qradar_tenant_id": tenant_id,
    #             }
    #         )

    #     return transformed
    def _transform_top_dos_data(self, data_list, integration_id, domain_id, date=None):
        name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
        tenant_id = name_to_id_map.get(domain_id)

        if not tenant_id:
            logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
            return []

        transformed = []
        for entry in data_list:
            event_name = entry.get("event_name")
            event_count = entry.get("event_count")
            if event_name is None or event_count is None:
                logger.warning(f"Skipping invalid top DoS data: {entry}")
                continue

            if date is None:
                transformed.append(
                    {
                        "event_name": event_name,
                        "event_count": event_count,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                    }
                )
            else:
                transformed.append(
                    {
                        "event_name": event_name,
                        "event_count": event_count,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                        "created_at": date,
                    }
                )

        return transformed
    def _insert_top_dos_event_data(self, data):
        logger.info(f"Inserting {len(data)} TopDosEventLog records")
        records = [TopDosEventLog(**item) for item in data]

        try:
            with transaction.atomic():
                TopDosEventLog.objects.bulk_create(records)
                logger.success(f"Inserted TopDosEventLog records: {len(records)}")
        except Exception as e:
            logger.error(f"Error inserting TopDosEventLog records: {str(e)}")
            transaction.rollback()

    # def _transform_daily_event_data(self, data_list, integration_id, domain_id):
    #     name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
    #     tenant_id = name_to_id_map.get(domain_id)

    #     if not tenant_id:
    #         logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
    #         return []

    #     transformed = []
    #     for entry in data_list:
    #         date = entry.get("date")
    #         daily_count = entry.get("daily_count")
    #         if date is None or daily_count is None:
    #             logger.warning(f"Skipping invalid daily event data: {entry}")
    #             continue

    #         transformed.append(
    #             {
    #                 "date": date,
    #                 "daily_count": daily_count,
    #                 "integration_id": integration_id,
    #                 "qradar_tenant_id": tenant_id,
    #             }
    #         )

    #     return transformed
    def _transform_daily_event_data(self, data_list, integration_id, domain_id, date=None):
        name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
        tenant_id = name_to_id_map.get(domain_id)

        if not tenant_id:
            logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
            return []

        transformed = []
        for entry in data_list:
            event_date = entry.get("date")
            daily_count = entry.get("daily_count")
            if event_date is None or daily_count is None:
                logger.warning(f"Skipping invalid daily event data: {entry}")
                continue

            if date is None:
                transformed.append(
                    {
                        "date": event_date,
                        "daily_count": daily_count,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                    }
                )
            else:
                transformed.append(
                    {
                        "date": event_date,
                        "daily_count": daily_count,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                        "created_at": date,
                    }
                )

        return transformed


    def _insert_daily_event_data(self, data):
        logger.info(f"Inserting {len(data)} DailyEventLog records")
        records = [DailyEventLog(**item) for item in data]

        try:
            with transaction.atomic():
                DailyEventLog.objects.bulk_create(records)
                logger.success(f"Inserted DailyEventLog records: {len(records)}")
        except Exception as e:
            logger.error(f"Error inserting DailyEventLog records: {str(e)}")
            transaction.rollback()

    # def _transform_top_alert_data(self, data_list, integration_id, domain_id):
    #     name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
    #     tenant_id = name_to_id_map.get(domain_id)

    #     if not tenant_id:
    #         logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
    #         return []

    #     transformed = []
    #     for entry in data_list:
    #         alert_name = entry.get("alert_name")
    #         event_count = entry.get("event_count")
    #         if alert_name is None or event_count is None:
    #             logger.warning(f"Skipping invalid top alert data: {entry}")
    #             continue

    #         transformed.append(
    #             {
    #                 "alert_name": alert_name,
    #                 "event_count": event_count,
    #                 "integration_id": integration_id,
    #                 "qradar_tenant_id": tenant_id,
    #             }
    #         )

    #     return transformed
    def _transform_top_alert_data(self, data_list, integration_id, domain_id, date=None):
        name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
        tenant_id = name_to_id_map.get(domain_id)

        if not tenant_id:
            logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
            return []

        transformed = []
        for entry in data_list:
            alert_name = entry.get("alert_name")
            event_count = entry.get("event_count")
            if alert_name is None or event_count is None:
                logger.warning(f"Skipping invalid top alert data: {entry}")
                continue

            if date is None:
                transformed.append(
                    {
                        "alert_name": alert_name,
                        "event_count": event_count,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                    }
                )
            else:
                transformed.append(
                    {
                        "alert_name": alert_name,
                        "event_count": event_count,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                        "created_at": date,
                    }
                )

        return transformed

    def _insert_top_alert_event_data(self, data):
        logger.info(f"Inserting {len(data)} TopAlertEventLog records")
        records = [TopAlertEventLog(**item) for item in data]

        try:
            with transaction.atomic():
                TopAlertEventLog.objects.bulk_create(records)
                logger.success(f"Inserted TopAlertEventLog records: {len(records)}")
        except Exception as e:
            logger.error(f"Error inserting TopAlertEventLog records: {str(e)}")
            transaction.rollback()

    # def _transform_daily_closure_reason_data(
    #     self, data_list, integration_id, domain_id
    # ):
    #     name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
    #     tenant_id = name_to_id_map.get(domain_id)

    #     if not tenant_id:
    #         logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
    #         return []

    #     transformed = []
    #     for entry in data_list:
    #         date = entry.get("date")
    #         closure_reason = entry.get("closure_reason")
    #         reason_count = entry.get("reason_count")
    #         if date is None or closure_reason is None or reason_count is None:
    #             logger.warning(f"Skipping invalid daily closure reason data: {entry}")
    #             continue

    #         transformed.append(
    #             {
    #                 "date": date,
    #                 "closure_reason": closure_reason,
    #                 "reason_count": reason_count,
    #                 "integration_id": integration_id,
    #                 "qradar_tenant_id": tenant_id,
    #             }
    #         )

    #     return transformed
    def _transform_daily_closure_reason_data(
        self, data_list, integration_id, domain_id, date=None
    ):
        name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
        tenant_id = name_to_id_map.get(domain_id)

        if not tenant_id:
            logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
            return []

        transformed = []
        for entry in data_list:
            event_date = entry.get("date")
            closure_reason = entry.get("closure_reason")
            reason_count = entry.get("reason_count")
            if event_date is None or closure_reason is None or reason_count is None:
                logger.warning(f"Skipping invalid daily closure reason data: {entry}")
                continue

            if date is None:
                transformed.append(
                    {
                        "date": event_date,
                        "closure_reason": closure_reason,
                        "reason_count": reason_count,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                    }
                )
            else:
                transformed.append(
                    {
                        "date": event_date,
                        "closure_reason": closure_reason,
                        "reason_count": reason_count,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                        "created_at": date,
                    }
                )

        return transformed

    def _insert_daily_closure_reason_data(self, data):
        logger.info(f"Inserting {len(data)} DailyClosureReasonLog records")
        records = [DailyClosureReasonLog(**item) for item in data]

        try:
            with transaction.atomic():
                DailyClosureReasonLog.objects.bulk_create(records)
                logger.success(
                    f"Inserted DailyClosureReasonLog records: {len(records)}"
                )
        except Exception as e:
            logger.error(f"Error inserting DailyClosureReasonLog records: {str(e)}")
            transaction.rollback()

    # def _transform_monthly_avg_eps_data(self, data_list, integration_id, domain_id):
    #     name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
    #     tenant_id = name_to_id_map.get(domain_id)

    #     if not tenant_id:
    #         logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
    #         return []

    #     for entry in data_list:
    #         monthly_avg_eps = entry.get("monthly_avg_eps")
    #         if monthly_avg_eps is None:
    #             logger.warning(f"Skipping invalid monthly avg EPS data: {entry}")
    #             continue

    #         return [
    #             {
    #                 "monthly_avg_eps": monthly_avg_eps,
    #                 "integration_id": integration_id,
    #                 "qradar_tenant_id": tenant_id,
    #             }
    #         ]

    #     return []
    def _transform_monthly_avg_eps_data(self, data_list, integration_id, domain_id, date=None):
        name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
        tenant_id = name_to_id_map.get(domain_id)

        if not tenant_id:
            logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
            return []

        for entry in data_list:
            monthly_avg_eps = entry.get("monthly_avg_eps")
            if monthly_avg_eps is None:
                logger.warning(f"Skipping invalid monthly avg EPS data: {entry}")
                continue

            if date is None:
                return [
                    {
                        "monthly_avg_eps": monthly_avg_eps,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                    }
                ]
            else:
                return [
                    {
                        "monthly_avg_eps": monthly_avg_eps,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                        "created_at": date,
                    }
                ]

        return []

    def _insert_monthly_avg_eps_data(self, data):
        logger.info(f"Inserting {len(data)} MonthlyAvgEpsLog records")
        records = [MonthlyAvgEpsLog(**item) for item in data]

        try:
            with transaction.atomic():
                MonthlyAvgEpsLog.objects.bulk_create(records)
                logger.success(f"Inserted MonthlyAvgEpsLog records: {len(records)}")
        except Exception as e:
            logger.error(f"Error inserting MonthlyAvgEpsLog records: {str(e)}")
            transaction.rollback()

    # def _transform_last_month_avg_eps_data(self, data_list, integration_id, domain_id):
    #     name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
    #     tenant_id = name_to_id_map.get(domain_id)

    #     if not tenant_id:
    #         logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
    #         return []

    #     for entry in data_list:
    #         last_month_avg_eps = entry.get("last_month_avg_eps")
    #         if last_month_avg_eps is None:
    #             logger.warning(f"Skipping invalid last month avg EPS data: {entry}")
    #             continue

    #         return [
    #             {
    #                 "last_month_avg_eps": last_month_avg_eps,
    #                 "integration_id": integration_id,
    #                 "qradar_tenant_id": tenant_id,
    #             }
    #         ]

    #     return []
    def _transform_last_month_avg_eps_data(self, data_list, integration_id, domain_id, date=None):
        name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
        tenant_id = name_to_id_map.get(domain_id)

        if not tenant_id:
            logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
            return []

        for entry in data_list:
            last_month_avg_eps = entry.get("last_month_avg_eps")
            if last_month_avg_eps is None:
                logger.warning(f"Skipping invalid last month avg EPS data: {entry}")
                continue

            if date is None:
                return [
                    {
                        "last_month_avg_eps": last_month_avg_eps,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                    }
                ]
            else:
                return [
                    {
                        "last_month_avg_eps": last_month_avg_eps,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                        "created_at": date,
                    }
                ]

        return []
    def _insert_last_month_avg_eps_data(self, data):
        logger.info(f"Inserting {len(data)} LastMonthAvgEpsLog records")
        records = [LastMonthAvgEpsLog(**item) for item in data]

        try:
            with transaction.atomic():
                LastMonthAvgEpsLog.objects.bulk_create(records)
                logger.success(f"Inserted LastMonthAvgEpsLog records: {len(records)}")
        except Exception as e:
            logger.error(f"Error inserting LastMonthAvgEpsLog records: {str(e)}")
            transaction.rollback()

    # def _transform_weekly_avg_eps_data(self, data_list, integration_id, domain_id):
    #     name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
    #     tenant_id = name_to_id_map.get(domain_id)

    #     if not tenant_id:
    #         logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
    #         return []

    #     transformed = []
    #     for entry in data_list:
    #         week = entry.get("week")
    #         week_start = entry.get("week_start")
    #         weekly_avg_eps = entry.get("weekly_avg_eps")
    #         if week is None or week_start is None or weekly_avg_eps is None:
    #             logger.warning(f"Skipping invalid weekly avg EPS data: {entry}")
    #             continue

    #         transformed.append(
    #             {
    #                 "week": week,
    #                 "week_start": week_start,
    #                 "weekly_avg_eps": weekly_avg_eps,
    #                 "integration_id": integration_id,
    #                 "qradar_tenant_id": tenant_id,
    #             }
    #         )

    #     return transformed
    def _transform_weekly_avg_eps_data(self, data_list, integration_id, domain_id, date=None):
        name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
        tenant_id = name_to_id_map.get(domain_id)

        if not tenant_id:
            logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
            return []

        transformed = []
        for entry in data_list:
            week = entry.get("week")
            week_start = entry.get("week_start")
            weekly_avg_eps = entry.get("weekly_avg_eps")
            if week is None or week_start is None or weekly_avg_eps is None:
                logger.warning(f"Skipping invalid weekly avg EPS data: {entry}")
                continue

            if date is None:
                transformed.append(
                    {
                        "week": week,
                        "week_start": week_start,
                        "weekly_avg_eps": weekly_avg_eps,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                    }
                )
            else:
                transformed.append(
                    {
                        "week": week,
                        "week_start": week_start,
                        "weekly_avg_eps": weekly_avg_eps,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                        "created_at": date,
                    }
                )

        return transformed

    def _insert_weekly_avg_eps_data(self, data):
        logger.info(f"Inserting {len(data)} WeeklyAvgEpsLog records")
        records = [WeeklyAvgEpsLog(**item) for item in data]

        try:
            with transaction.atomic():
                WeeklyAvgEpsLog.objects.bulk_create(records)
                logger.success(f"Inserted WeeklyAvgEpsLog records: {len(records)}")
        except Exception as e:
            logger.error(f"Error inserting WeeklyAvgEpsLog records: {str(e)}")
            transaction.rollback()

    # def _transform_total_traffic_data(self, data_list, integration_id, domain_id):
    #     name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
    #     tenant_id = name_to_id_map.get(domain_id)

    #     if not tenant_id:
    #         logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
    #         return []

    #     for entry in data_list:
    #         total_traffic = entry.get("total_traffic")
    #         if total_traffic is None:
    #             logger.warning(f"Skipping invalid total traffic data: {entry}")
    #             continue

    #         return [
    #             {
    #                 "total_traffic": total_traffic,
    #                 "integration_id": integration_id,
    #                 "qradar_tenant_id": tenant_id,
    #             }
    #         ]

    #     return []
    
    def _transform_total_traffic_data(self, data_list, integration_id, domain_id, date=None):
            name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
            tenant_id = name_to_id_map.get(domain_id)

            if not tenant_id:
                logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
                return []

            for entry in data_list:
                total_traffic = entry.get("total_traffic")
                if total_traffic is None:
                    logger.warning(f"Skipping invalid total traffic data: {entry}")
                    continue

                if date is None:
                    return [
                        {
                            "total_traffic": total_traffic,
                            "integration_id": integration_id,
                            "qradar_tenant_id": tenant_id,
                        }
                    ]
                else:
                    return [
                        {
                            "total_traffic": total_traffic,
                            "integration_id": integration_id,
                            "qradar_tenant_id": tenant_id,
                            "created_at": date,
                        }
                    ]

            return []

    def _insert_total_traffic_data(self, data):
        logger.info(f"Inserting {len(data)} TotalTrafficLog records")
        records = [TotalTrafficLog(**item) for item in data]

        try:
            with transaction.atomic():
                TotalTrafficLog.objects.bulk_create(records)
                logger.success(f"Inserted TotalTrafficLog records: {len(records)}")
        except Exception as e:
            logger.error(f"Error inserting TotalTrafficLog records: {str(e)}")
            transaction.rollback()

    # def _transform_destination_address_data(self, data_list, integration_id, domain_id):
    #     name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
    #     tenant_id = name_to_id_map.get(domain_id)

    #     if not tenant_id:
    #         logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
    #         return []

    #     transformed = []
    #     for entry in data_list:
    #         destination_address = entry.get("destinationaddress")
    #         address_count = entry.get("address_count")
    #         if destination_address is None or address_count is None:
    #             logger.warning(f"Skipping invalid destination address data: {entry}")
    #             continue

    #         transformed.append(
    #             {
    #                 "destination_address": destination_address,
    #                 "address_count": address_count,
    #                 "integration_id": integration_id,
    #                 "qradar_tenant_id": tenant_id,
    #             }
    #         )

    #     return transformed
    def _transform_destination_address_data(self, data_list, integration_id, domain_id, date=None):
        name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
        tenant_id = name_to_id_map.get(domain_id)

        if not tenant_id:
            logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
            return []

        transformed = []
        for entry in data_list:
            destination_address = entry.get("destinationaddress")
            address_count = entry.get("address_count")
            if destination_address is None or address_count is None:
                logger.warning(f"Skipping invalid destination address data: {entry}")
                continue

            if date is None:
                transformed.append(
                    {
                        "destination_address": destination_address,
                        "address_count": address_count,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                    }
                )
            else:
                transformed.append(
                    {
                        "destination_address": destination_address,
                        "address_count": address_count,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                        "created_at": date,
                    }
                )

        return transformed


    def _insert_destination_address_data(self, data):
        logger.info(f"Inserting {len(data)} DestinationAddressLog records")
        records = [DestinationAddressLog(**item) for item in data]

        try:
            with transaction.atomic():
                DestinationAddressLog.objects.bulk_create(records)
                logger.success(
                    f"Inserted DestinationAddressLog records: {len(records)}"
                )
        except Exception as e:
            logger.error(f"Error inserting DestinationAddressLog records: {str(e)}")
            transaction.rollback()

    def _transform_top_destination_connection_data(
        self, data_list, integration_id, domain_id
    ):
        name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
        tenant_id = name_to_id_map.get(domain_id)

        if not tenant_id:
            logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
            return []

        transformed = []
        for entry in data_list:
            destination_address = entry.get("destinationaddress")
            connection_count = entry.get("connection_count")
            if destination_address is None or connection_count is None:
                logger.warning(
                    f"Skipping invalid top destination connection data: {entry}"
                )
                continue

            transformed.append(
                {
                    "destination_address": destination_address,
                    "connection_count": connection_count,
                    "integration_id": integration_id,
                    "qradar_tenant_id": tenant_id,
                }
            )

        return transformed

    def _insert_top_destination_connection_data(self, data):
        logger.info(f"Inserting {len(data)} TopDestinationConnectionLog records")
        records = [TopDestinationConnectionLog(**item) for item in data]

        try:
            with transaction.atomic():
                TopDestinationConnectionLog.objects.bulk_create(records)
                logger.success(
                    f"Inserted TopDestinationConnectionLog records: {len(records)}"
                )
        except Exception as e:
            logger.error(
                f"Error inserting TopDestinationConnectionLog records: {str(e)}"
            )
            transaction.rollback()

    def _transform_daily_event_count_data(self, data_list, integration_id, domain_id):
        name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
        tenant_id = name_to_id_map.get(domain_id)

        if not tenant_id:
            logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
            return []

        transformed = []
        for entry in data_list:
            full_date = entry.get("full_date")
            daily_count = entry.get("daily_count")
            if full_date is None or daily_count is None:
                logger.warning(f"Skipping invalid daily event count data: {entry}")
                continue

            transformed.append(
                {
                    "full_date": full_date,
                    "daily_count": daily_count,
                    "integration_id": integration_id,
                    "qradar_tenant_id": tenant_id,
                }
            )

        return transformed

    def _insert_daily_event_count_data(self, data):
        logger.info(f"Inserting {len(data)} DailyEventCountLog records")
        records = [DailyEventCountLog(**item) for item in data]

        try:
            with transaction.atomic():
                DailyEventCountLog.objects.bulk_create(records)
                logger.success(f"Inserted DailyEventCountLog records: {len(records)}")
        except Exception as e:
            logger.error(f"Error inserting DailyEventCountLog records: {str(e)}")
            transaction.rollback()

    # ibm_qradar.py
    def _transform_successful_logon_data(
        self, data_list, integration_id, domain_id, full_date
    ):
        name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
        tenant_id = name_to_id_map.get(domain_id)

        if not tenant_id:
            logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
            return []

        transformed = []
        for entry in data_list:
            try:
                transformed.append(
                    {
                        "username": entry.get("username"),
                        "logon_type": entry.get("logon_type"),
                        "source_ip": entry.get("sourceip"),
                        "log_source": entry.get("log_source"),
                        "event_count": float(entry.get("event_count", 0)),
                        "full_date": full_date,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                    }
                )
            except Exception as e:
                logger.error(f"Error transforming logon data {entry}: {str(e)}")
                continue

        return transformed

    def _insert_successful_logon_data(self, data):
        logger.info(f"Inserting {len(data)} SuccessfulLogonEvent records")
        records = [SuccessfulLogonEvent(**item) for item in data]

        try:
            with transaction.atomic():
                SuccessfulLogonEvent.objects.bulk_create(records)
                logger.success(f"Inserted SuccessfulLogonEvent records: {len(records)}")
        except Exception as e:
            logger.error(f"Error inserting SuccessfulLogonEvent records: {str(e)}")
            transaction.rollback()

    # ibm_qradar.py
    def _transform_remote_users_data(
        self, data_list, integration_id, domain_id, full_date
    ):
        name_to_id_map = DBMappings.get_db_id_to_id_mapping(DuIbmQradarTenants)
        tenant_id = name_to_id_map.get(domain_id)

        if not tenant_id:
            logger.warning(f"No QRadar tenant found for domain_id: {domain_id}")
            return []

        transformed = []
        for entry in data_list:
            try:
                transformed.append(
                    {
                        "total_remote_users": float(entry.get("total_remote_users", 0)),
                        "full_date": full_date,
                        "integration_id": integration_id,
                        "qradar_tenant_id": tenant_id,
                    }
                )
            except Exception as e:
                logger.error(f"Error transforming remote users data {entry}: {str(e)}")
                continue

        return transformed

    def _insert_remote_users_data(self, data):
        if not data:
            logger.warning("No remote users data to insert")
            return

        logger.info(f"Inserting {len(data)} RemoteUsersCount records")
        records = [RemoteUsersCount(**item) for item in data]

        try:
            with transaction.atomic():
                RemoteUsersCount.objects.bulk_create(records)
                logger.success(f"Inserted RemoteUsersCount records: {len(records)}")
        except Exception as e:
            logger.error(f"Error inserting RemoteUsersCount records: {str(e)}")
            transaction.rollback()
