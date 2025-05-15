import json
import os
import time

import pandas as pd
import requests
from django.db import transaction
from loguru import logger

from common.constants import CortexSOARConstants, SSLConstants
from tenant.models import DuCortexSOARTenants


class CortexSOAR:
    def __init__(self, ip_address: str, port: int, token: str):
        """
        Constructor for CortexSOAR class.

        :param ip_address: The IP address of the CortexSOAR.
        :param port: The port number of the CortexSOAR.
        :param token: The token to use when logging into the CortexSOAR.
        :raises ValueError: If either the token, ip_address or port are not set.
        """
        self.token = token
        self.ip_address = ip_address
        self.port = port
        if not self.token or not self.ip_address or not self.port:
            logger.error("CortexSOAR both token, ip_address and port are required")
            raise ValueError("CortexSOAR both token, ip_address and port are required")
        self.base_url = self._get_base_url()
        self.headers = {"Accept": "application/json", "Authorization": token}

    def __enter__(self):
        """
        Enter the runtime context related to this object.

        This method logs the entry into the CortexSOAR context and
        prepares the object for use with a context manager (e.g., with statement).

        :return: Returns self after logging the entry.
        """

        logger.info("Logging into CortexSOAR")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        logger.info("Logging out of CortexSOAR")

    def _get_base_url(self):
        if self.port != 80:
            return f"https://{self.ip_address}:{self.port}"
        return f"https://{self.ip_address}"

    def _get_accounts_test(self):
        """
        Fetches the list of accounts from the CortexSOAR instance by reading the test data from a local file.

        This method is used for testing purposes only. It reads the data from a local file
        and returns it as a JSON object. The file should contain the list of accounts in the
        same format as the data returned by the CortexSOAR API.

        :return: A JSON object containing the list of accounts.
        """
        start = time.time()
        logger.info(f"CortexSOAR._get_accounts() started : {start}")
        file_path = f"{os.getcwd()}/soar.json"
        with open(file_path, "r") as f:
            data = json.load(f)
        logger.info(f"CortexSOAR._get_accounts() took: {time.time() - start} seconds")
        return data

    def _get_accounts(self):
        """
        Fetches the list of accounts from the CortexSOAR instance.

        This method sends an HTTP GET request to the CortexSOAR accounts API endpoint
        to retrieve the list of accounts. It uses HTTP basic authentication with the token
        set in the CortexSOarConstants. If the request is successful, it returns the parsed
        JSON response. If the request fails or an exception occurs, it logs an error and
        returns an empty list.

        :return: A list of accounts if the request is successful, otherwise an empty list.
        :raises: Logs any exceptions that occur during the request.
        """
        start = time.time()
        logger.info(f"CortexSOAR._get_accounts() started : {start}")
        endpoint = f"{self.base_url}/{CortexSOARConstants.TENANT_ENDPOINT}"
        try:
            response = requests.get(
                endpoint,
                headers=self.headers,
                verify=SSLConstants.VERIFY,
                timeout=SSLConstants.TIMEOUT,
            )
        except Exception as e:
            logger.error(f"CortexSOAR._get_accounts() failed with exception : {str(e)}")

        if response.status_code != 200:
            logger.warning(
                f"CortexSOAR._get_accounts() return the status code {response.status_code}"
            )
            return

        data = response.json()
        return data

    def _transform_accounts(self, accounts: dict, integration_id: int):
        """
        Transforms the list of accounts into a list of dictionaries.

        :param accounts: The list of accounts to transform.
        :return: A list of dictionaries representing the transformed accounts.
        """
        df = pd.DataFrame(accounts)
        df = df[["id", "name"]]
        df.rename(columns={"id": "db_id"}, inplace=True)
        df["integration_id"] = integration_id
        results = df.to_dict(orient="records")
        return results

    def _insert_accounts(self, accounts: dict):
        """
        Inserts or updates account records in the DuCortexSOARTenants table.

        :param accounts: A list of dictionaries containing account information.
        """
        start = time.time()
        logger.info(f"CortexSOAR._insert_accounts() started : {start}")
        records = [DuCortexSOARTenants(**item) for item in accounts]
        logger.info(f"Inserting the accounts records: {len(records)}")
        try:
            with transaction.atomic():
                DuCortexSOARTenants.objects.bulk_create(
                    records,
                    update_conflicts=True,
                    update_fields=["name"],
                    unique_fields=["db_id"],
                )
                logger.info(f"Inserted the accounts records: {len(records)}")
                logger.success(
                    f"CortexSOAR._insert_accounts() took: {time.time() - start} seconds"
                )
        except Exception as e:
            logger.error(
                f"An error occurred in CortexSOAR._insert_accounts(): {str(e)}"
            )
            transaction.rollback()
