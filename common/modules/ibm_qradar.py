import time

import pandas as pd
import requests
from django.db import transaction
from loguru import logger
from requests.auth import HTTPBasicAuth

from common.constants import IBMQradarConstants, SSLConstants
from common.utils import DBMappings
from tenant.models import DuIbmQradarTenants, IBMQradarAssests, IBMQradarEventCollector


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
                "modified_date",
                "last_event_time",
                "integration_id",
            ]
        ]
        df.rename(columns={"id": "db_id", "status_value": "status"}, inplace=True)
        df.dropna(subset=["target_event_collector_id"], inplace=True)
        df["event_collector_id"] = df["target_event_collector_id"].map(collector_map)
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
                        "event_collector_id_id",
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
