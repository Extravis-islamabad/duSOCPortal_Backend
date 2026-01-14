import time

import requests
from loguru import logger

from common.constants import EnvConstants, FortiSOARConstants, SSLConstants


class FortiSOAR:
    def __init__(self, ip_address: str, port: int, token: str):
        """
        Constructor for FortiSOAR class.

        :param ip_address: The IP address of the FortiSOAR.
        :param port: The port number of the FortiSOAR.
        :param token: The token to use when logging into the FortiSOAR.
        :raises ValueError: If either the token, ip_address or port are not set.
        """
        self.token = token
        self.ip_address = ip_address
        self.port = port
        if not self.token or not self.ip_address or not self.port:
            logger.error("FortiSOAR both token, ip_address and port are required")
            raise ValueError("FortiSOAR both token, ip_address and port are required")
        self.headers = {
            "Accept": "application/json",
            "Authorization": f"API-KEY {token}",
        }
        self.base_url = self._get_base_url()
        # self.headers = {"Accept": "application/json", "Authorization": token}

    def __enter__(self):
        """
        Enter the runtime context related to this object.

        This method logs the entry into the FortiSOAR context and
        prepares the object for use with a context manager (e.g., with statement).

        :return: Returns self after logging the entry.
        """

        logger.info("Logging into FortiSOAR")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        logger.info("Logging out of FortiSOAR")

    def _get_base_url(self):
        if self.port != 80:
            return f"https://{self.ip_address}:{self.port}"
        return f"https://{self.ip_address}"

    def _get_tenants(self, timeout=SSLConstants.TIMEOUT):
        """
        Fetches the list of tenants from the FortiSOAR endpoint.

        This method sends an HTTP GET request to the FortiSOAR tenant management API endpoint
        to retrieve the list of tenants. It uses HTTP basic authentication with the credentials
        set in the FortiSOARConstants. If the request is successful, it returns the parsed JSON
        response. If the request fails or an exception occurs, it logs an error and returns an
        empty dictionary.

        :param timeout: The timeout in seconds for the HTTP request.
        :return: A dictionary containing tenant information if the request is successful, otherwise an empty dictionary.
        :raises: Logs any exceptions that occur during the request.
        """
        start = time.time()
        logger.info(f"FortiSOAR._get_tenants() started : {start}")
        endpoint = f"{self.base_url}/{FortiSOARConstants.TENANT_ENDPOINT}"
        try:
            if EnvConstants.LOCAL:
                proxies = {
                    "http": "http://127.0.0.1:8080",
                    "https": "http://127.0.0.1:8080",
                }
                response = requests.get(
                    endpoint,
                    headers=self.headers,
                    verify=SSLConstants.VERIFY,
                    proxies=proxies,
                    timeout=timeout,
                )
            else:
                response = requests.get(
                    endpoint,
                    headers=self.headers,
                    verify=SSLConstants.VERIFY,
                    timeout=timeout,
                )
        except Exception as e:
            logger.error(f"FortiSOAR._get_tenants() failed with exception : {str(e)}")
            raise Exception(
                f"FortiSOAR._get_tenants() failed with exception : {str(e)}"
            )
        if response.status_code != 200:
            logger.warning(
                f"FortiSOAR._get_tenants() return the status code {response.status_code}"
            )
            raise Exception(
                f"FortiSOAR._get_tenants() return the status code {response.status_code}"
            )

        data = response.json()
        return data

    def _get_alerts(self, tenant_name: str, timeout=SSLConstants.TIMEOUT):
        start = time.time()
        logger.info(f"FortiSOAR._get_alerts() started : {start}")
        endpoint = f"{self.base_url}/{FortiSOARConstants.ALERTS_ENDPOINT}?tenant__name={tenant_name}"
        try:
            if EnvConstants.LOCAL:
                proxies = {
                    "http": "http://127.0.0.1:8080",
                    "https": "http://127.0.0.1:8080",
                }
                response = requests.get(
                    endpoint,
                    headers=self.headers,
                    verify=SSLConstants.VERIFY,
                    proxies=proxies,
                    timeout=timeout,
                )
            else:
                response = requests.get(
                    endpoint,
                    headers=self.headers,
                    verify=SSLConstants.VERIFY,
                    timeout=timeout,
                )
        except Exception as e:
            logger.error(f"FortiSOAR._get_alerts() failed with exception : {str(e)}")
            raise Exception(f"FortiSOAR._get_alerts() failed with exception : {str(e)}")
        if response.status_code != 200:
            logger.warning(
                f"FortiSOAR._get_alerts() return the status code {response.status_code}"
            )
            raise Exception(
                f"FortiSOAR._get_alerts() return the status code {response.status_code}"
            )

        data = response.json()
        return data

    def _get_notes(self, tenant_name: str, timeout=SSLConstants.TIMEOUT):
        start = time.time()
        logger.info(f"FortiSOAR._get_alerts() started : {start}")
        endpoint = f"{self.base_url}/{FortiSOARConstants.ALERTS_ENDPOINT}?tenant__name={tenant_name}"
        try:
            if EnvConstants.LOCAL:
                proxies = {
                    "http": "http://127.0.0.1:8080",
                    "https": "http://127.0.0.1:8080",
                }
                response = requests.get(
                    endpoint,
                    headers=self.headers,
                    verify=SSLConstants.VERIFY,
                    proxies=proxies,
                    timeout=timeout,
                )
            else:
                response = requests.get(
                    endpoint,
                    headers=self.headers,
                    verify=SSLConstants.VERIFY,
                    timeout=timeout,
                )
        except Exception as e:
            logger.error(f"FortiSOAR._get_alerts() failed with exception : {str(e)}")
            raise Exception(f"FortiSOAR._get_alerts() failed with exception : {str(e)}")
        if response.status_code != 200:
            logger.warning(
                f"FortiSOAR._get_alerts() return the status code {response.status_code}"
            )
            raise Exception(
                f"FortiSOAR._get_alerts() return the status code {response.status_code}"
            )

        data = response.json()
        return data
