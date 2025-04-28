import time

import requests
from loguru import logger
from requests.auth import HTTPBasicAuth

from common.constants import IBMQradarConstants, SSLConstants


class IBMQradar:
    def __init__(self, username, password):
        """
        Constructor for IBMQRadar class.

        :param username: The username to use when logging into the QRadar.
        :param password: The password to use when logging into the QRadar.
        :raises ValueError: If either the username or password are not set.
        """
        self.username = username
        self.password = password
        if not self.username or not self.password:
            logger.error("IBM QRadar both username and password are required")
            raise ValueError("Both username and password are required")

    def __enter__(self):
        logger.info(f"Logging into IBM QRadar with username: {self.username}")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        logger.info("Logging out of IBM QRadar")

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
        try:
            response = requests.get(
                IBMQradarConstants.IBM_TENANT_ENDPOINT,
                auth=HTTPBasicAuth(
                    IBMQradarConstants.IBM_QRADAR_USERNAME,
                    IBMQradarConstants.IBM_QRADAR_PASSWORD,
                ),
                verify=SSLConstants.VERIFY,  # TODO : Handle this to TRUE in production
                timeout=10,
            )
            if response.status_code != 200:
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
        try:
            response = requests.get(
                IBMQradarConstants.IBM_DOMAIN_ENDPOINT,
                auth=HTTPBasicAuth(
                    IBMQradarConstants.IBM_QRADAR_USERNAME,
                    IBMQradarConstants.IBM_QRADAR_PASSWORD,
                ),
                verify=SSLConstants.VERIFY,  # TODO : Handle this to TRUE in production
                timeout=10,
            )
            if response.status_code != 200:
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
        try:
            response = requests.get(
                IBMQradarConstants.IBM_EVENT_COLLECTOR_ENDPOINT,
                auth=HTTPBasicAuth(
                    IBMQradarConstants.IBM_QRADAR_USERNAME,
                    IBMQradarConstants.IBM_QRADAR_PASSWORD,
                ),
                verify=SSLConstants.VERIFY,  # TODO : Handle this to TRUE in production
                timeout=10,
            )
            if response.status_code != 200:
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
        try:
            response = requests.get(
                IBMQradarConstants.IBM_EVENT_LOGS_ENDPOINT,
                auth=HTTPBasicAuth(
                    IBMQradarConstants.IBM_QRADAR_USERNAME,
                    IBMQradarConstants.IBM_QRADAR_PASSWORD,
                ),
                verify=SSLConstants.VERIFY,  # TODO : Handle this to TRUE in production
                timeout=10,
            )
            if response.status_code != 200:
                return
            logs = response.json()
            logger.success(
                f"IBMQRadar._get_event_logs() took: {time.time() - start} seconds"
            )
            return logs

        except Exception as e:
            logger.error(f"An error occurred in IBMQradar.__get_event_logs(): {str(e)}")
