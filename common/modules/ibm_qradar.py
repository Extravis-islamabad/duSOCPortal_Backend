import time

import pandas as pd
import requests
from django.db import transaction
from loguru import logger
from requests.auth import HTTPBasicAuth

from common.constants import IBMQradarConstants, SSLConstants
from common.utils import DBMappings
from tenant.models import (
    DuIbmQradarTenants,
    IBMQradarAssests,
    IBMQradarEventCollector,
    IBMQradarLogSourceTypes,
    IBMQradarOffense,
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

    def test_integration(self):
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
                timeout=SSLConstants.TIMEOUT,
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
