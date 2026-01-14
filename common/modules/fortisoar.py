import time

import pandas as pd
import requests
from django.db import transaction
from loguru import logger

from common.constants import EnvConstants, FortiSOARConstants, SSLConstants
from tenant.models import FortiSOARTenants


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
        """
        Fetches the list of alerts from the FortiSOAR endpoint.

        This method sends an HTTP GET request to the FortiSOAR alerts API endpoint
        to retrieve the list of alerts for a given tenant. It uses HTTP basic authentication
        with the credentials set in the FortiSOARConstants. If the request is successful, it returns
        the parsed JSON response. If the request fails or an exception occurs, it logs an error
        and returns an empty dictionary.

        :param tenant_name: The name of the tenant.
        :param timeout: The timeout for the request in seconds.
        :return: A dictionary containing alert information if the request is successful, otherwise an empty dictionary.
        :raises: Logs any exceptions that occur during the request.
        """
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

    def transform_tenants(self, data, integration_id):
        """
        Transforms the list of tenants from the FortiSOAR API response into a list of dictionaries.

        :param data: A dictionary containing the FortiSOAR API response.
        :param integration_id: The integration ID to be associated with the tenants.
        :return: A list of dictionaries containing the transformed tenant information.
        """
        tenants_data = data.get("hydra:member", [])

        if not tenants_data:
            logger.warning("No tenants found in FortiSOAR API response")
            return []

        df = pd.DataFrame(tenants_data)
        df = df[["id", "name"]]
        df.rename(columns={"id": "db_id"}, inplace=True)
        df["integration_id"] = integration_id
        results = df.to_dict(orient="records")
        return results

    def _insert_tenants(self, accounts: dict):
        """
        Inserts or updates tenant records in the FortiSOARTenants table.

        :param accounts: A list of dictionaries containing tenant information.
        """
        start = time.time()
        logger.info(f"FortiSOAR._insert_accounts() started : {start}")
        records = [FortiSOARTenants(**item) for item in accounts]
        logger.info(f"Inserting the accounts records: {len(records)}")
        try:
            with transaction.atomic():
                FortiSOARTenants.objects.bulk_create(
                    records,
                    update_conflicts=True,
                    update_fields=["name"],
                    unique_fields=["db_id"],
                )
                logger.info(f"Inserted the accounts records: {len(records)}")
                logger.success(
                    f"FortiSOAR._insert_accounts() took: {time.time() - start} seconds"
                )
        except Exception as e:
            logger.error(f"An error occurred in FortiSOAR._insert_accounts(): {str(e)}")
            transaction.rollback()
