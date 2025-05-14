import json
import os
import time

import pandas as pd
import requests
from django.db import transaction
from loguru import logger

from common.constants import ITSMConstants, SSLConstants
from tenant.models import DuITSMTenants


class ITSM:
    def __init__(self, ip_address: str, port: int, token: str):
        """
        Constructor for ITSM class.

        :param ip_address: The IP address of the ITSM.
        :param port: The port number of the ITSM.
        :param token: The token to use when logging into the ITSM.
        :raises ValueError: If either the token, ip_address or port are not set.
        """
        self.auth_token = token
        self.ip_address = ip_address
        self.port = port
        if not self.auth_token or not self.ip_address or not self.port:
            logger.error("ITSM both auth_token, ip_address and port are required")
            raise ValueError("Both auth_token, ip_address and port are required")
        self.base_url = self._get_base_url()
        self.headers = {"authtoken": self.auth_token}

    def __enter__(self):
        """
        Enter the runtime context related to this object.

        This method logs the entry into the ITSM context and
        prepares the object for use with a context
        manager (e.g., with statement).

        :return: Returns self after logging the entry.
        """
        logger.info("Logging into ITSM")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Exit the runtime context related to this object.

        This method logs the exit from the ITSM context and
        performs any necessary cleanup.

        :param exc_type: The type of exception thrown, if any.
        :param exc_value: The value of the exception thrown, if any.
        :param traceback: The traceback of the exception thrown, if any.
        """
        logger.info("Logging out of ITSM")

    def _get_base_url(self):
        """
        Return the base URL of the ITSM instance.

        :return: The base URL of the ITSM instance.
        """
        if self.port != 80:
            return f"https://{self.ip_address}:{self.port}"
        return f"https://{self.ip_address}"

    def _get_accounts_test(self):
        """
        Fetches the list of accounts from the ITSM instance.

        This method sends an HTTP GET request to the ITSM accounts API endpoint
        to retrieve the list of accounts. It uses HTTP basic authentication with the credentials
        set in the ITSMConstants. If the request is successful, it returns the parsed JSON
        response. If the request fails or an exception occurs, it logs an error and returns an
        empty list.

        :return: A list of accounts if the request is successful, otherwise an empty list.
        :raises: Logs any exceptions that occur during the request.
        """
        start = time.time()
        logger.info(f"ITSM._get_accounts() started : {start}")
        file_path = f"{os.getcwd()}/itsm_data.json"
        with open(file_path, "r") as f:
            data = json.load(f)
        accounts = data.get("accounts", [])
        logger.info(f"ITSM._get_accounts() took: {time.time() - start} seconds")
        return accounts

    def _get_accounts(self):
        """
        Fetches the list of accounts from the ITSM instance.

        This method sends an HTTP GET request to the ITSM accounts API endpoint
        to retrieve the list of accounts. It uses HTTP basic authentication with the credentials
        set in the ITSMConstants. If the request is successful, it returns the parsed JSON
        response. If the request fails or an exception occurs, it logs an error and returns an
        empty list.

        :return: A list of accounts if the request is successful, otherwise an empty list.
        :raises: Logs any exceptions that occur during the request.
        """
        start = time.time()
        logger.info(f"ITSM._get_accounts() started : {start}")
        endpoint = f"{self.base_url}/{ITSMConstants.ITSM_ACCOUNTS_ENDPOINT}"

        start_index = ITSMConstants.ITSM_START_INDEX
        row_count = ITSMConstants.ITSM_ROW_COUNT
        has_more_rows = True

        all_accounts = []

        while has_more_rows:
            input_data = {
                "list_info": {
                    "row_count": str(row_count),
                    "start_index": str(start_index),
                    "sort_field": "name",
                    "sort_order": "asc",
                }
            }

            params = {"input_data": json.dumps(input_data)}

            try:
                response = requests.get(
                    endpoint,
                    headers=self.headers,
                    params=params,
                    verify=SSLConstants.VERIFY,
                    timeout=SSLConstants.TIMEOUT,
                )
            except Exception as e:
                logger.error(f"ITSM._get_accounts() failed with exception: {str(e)}")
                break

            if response.status_code != 200:
                logger.warning(
                    f"ITSM._get_accounts() return the status code {response.status_code}"
                )
                break

            data = response.json()
            if (
                data["response_status"][0]["status_code"] != ITSMConstants.STATUS_CODE
                or data["response_status"][0]["status"] != ITSMConstants.SUCCESS
            ):
                logger.warning(
                    f"ITSM._get_accounts() return the status code {data['response_status'][0]['status_code']} and status {data['response_status'][0]['status']}"
                )
                break

            logger.info(f"Fetching rows starting from index: {start_index}")

            accounts = data.get("accounts", [])
            all_accounts.extend(accounts)

            list_info = data.get("list_info", {})
            has_more_rows = list_info.get("has_more_rows", False)
            start_index = list_info.get("start_index", start_index) + row_count

        logger.info(f"ITSM._get_accounts() took: {time.time() - start} seconds")
        return all_accounts

    def _transform_accounts(self, accounts: dict, integration_id: int):
        """
        Transforms the list of accounts into a list of dictionaries.

        :param accounts: The list of accounts to transform.
        :return: A list of dictionaries representing the transformed accounts.
        """
        df = pd.DataFrame(accounts)
        df.rename(columns={"id": "db_id"}, inplace=True)
        df["integration_id"] = integration_id
        results = df.to_dict(orient="records")
        return results

    def _insert_accounts(self, accounts: dict):
        """
        Inserts or updates accounts in the DuIbmQradarTenants table.

        :param accounts: A list of dictionaries containing account information.
        """
        start = time.time()
        logger.info(f"ITSM._insert_accounts() started : {start}")
        records = [DuITSMTenants(**item) for item in accounts]
        logger.info(f"Inserting the accounts records: {len(records)}")
        try:
            with transaction.atomic():
                DuITSMTenants.objects.bulk_create(
                    records,
                    update_conflicts=True,
                    update_fields=["name"],
                    unique_fields=["db_id"],
                )
                logger.info(f"Inserted the accounts records: {len(records)}")
                logger.success(
                    f"ITSM._insert_accounts() took: {time.time() - start} seconds"
                )
        except Exception as e:
            logger.error(f"An error occurred in ITSM._insert_accounts(): {str(e)}")
            transaction.rollback()
