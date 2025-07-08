import json
import os
import time

import pandas as pd
import requests
from django.db import transaction
from loguru import logger

from common.constants import ITSMConstants, SSLConstants
from tenant.models import DuITSMFinalTickets, DuITSMTenants


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

    def _get_accounts(self, timeout=SSLConstants.TIMEOUT):
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
                    timeout=timeout,
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

    def _get_requests(self, account_id: int):
        start = time.time()
        logger.info(f"ITSM._get_requests() started : {start}")
        logger.info(f"Fetching requests for account id: {account_id}")

        endpoint = f"{self.base_url}/{ITSMConstants.ITSM_REQUESTS_ENDPOINT}?ACCOUNTID={account_id}"
        row_count = 1000
        start_index = 1
        all_requests = []
        has_more_rows = True

        while has_more_rows:
            input_data = {
                "list_info": {
                    "row_count": str(row_count),
                    "start_index": str(start_index),
                    "sort_order": "asc",
                }
            }

            params = {"input_data": json.dumps(input_data)}

            try:
                response = requests.get(
                    endpoint,
                    headers=self.headers,
                    params=params,
                    verify=SSLConstants.VERIFY,  # self-signed cert assumed
                    timeout=SSLConstants.TIMEOUT,
                )
            except Exception as e:
                logger.error(f"ITSM._get_requests() failed with exception: {str(e)}")
                return

            if response.status_code != 200:
                logger.warning(
                    f"ITSM._get_requests() return the status code {response.status_code}"
                )
                break

            data = response.json()

            # Append current batch of requests
            requests_batch = data.get("requests", [])
            all_requests.extend(requests_batch)

            # Pagination control
            list_info = data.get("list_info", {})
            has_more_rows = list_info.get("has_more_rows", False)
            start_index = list_info.get("start_index", start_index) + row_count

        logger.info(f"ITSM._get_requests() took: {time.time() - start} seconds")
        return all_requests

    def _get_soar_ids(self, account_id: int):
        start = time.time()
        logger.info(f"ITSM._get_requests() started : {start}")
        logger.info(f"Fetching requests for account id: {account_id}")

        endpoint = f"{self.base_url}/{ITSMConstants.ITSM_REQUESTS_ENDPOINT}?ACCOUNTID={account_id}"
        row_count = 1000
        start_index = 1
        all_requests = []
        has_more_rows = True

        while has_more_rows:
            input_data = {
                "list_info": {
                    "row_count": str(row_count),
                    "start_index": str(start_index),
                    "sort_order": "asc",
                    "fields_required": ["udf_fields.udf_sline_4506"],
                }
            }

            params = {"input_data": json.dumps(input_data)}

            try:
                response = requests.get(
                    endpoint,
                    headers=self.headers,
                    params=params,
                    verify=SSLConstants.VERIFY,  # self-signed cert assumed
                    timeout=SSLConstants.TIMEOUT,
                )
            except Exception as e:
                logger.error(f"ITSM._get_requests() failed with exception: {str(e)}")
                return

            if response.status_code != 200:
                logger.warning(
                    f"ITSM._get_requests() return the status code {response.status_code}"
                )
                break

            data = response.json()

            # Append current batch of requests
            requests_batch = data.get("requests", [])
            all_requests.extend(requests_batch)

            # Pagination control
            list_info = data.get("list_info", {})
            has_more_rows = list_info.get("has_more_rows", False)
            start_index = list_info.get("start_index", start_index) + row_count

        logger.info(f"ITSM._get_requests() took: {time.time() - start} seconds")
        return all_requests

    def get_soar_id(self, request_id: int):
        """
        Retrieves the SOAR ID for a specific request from the ITSM system.

        This method sends an HTTP GET request to the ITSM API to fetch the SOAR ID
        associated with the given request ID. It logs the start and completion time
        of the request. If the request is successful, it returns the SOAR ID. If
        the request fails or an exception occurs, it logs an error and returns None.

        :param request_id: The unique identifier for the request.
        :return: The SOAR ID if the request is successful, otherwise None.
        :raises: Logs any exceptions that occur during the request.
        """

        start = time.time()
        logger.info(
            f"ITSM.get_soar_id() started : {start} for the request id: {request_id}"
        )

        endpoint = (
            f"{self.base_url}/{ITSMConstants.ITSM_REQUESTS_ENDPOINT}/{request_id}"
        )
        try:
            response = requests.get(
                endpoint,
                headers=self.headers,
                verify=SSLConstants.VERIFY,  # self-signed cert assumed
                timeout=SSLConstants.TIMEOUT,
            )
        except Exception as e:
            logger.error(f"ITSM.get_soar_id() failed with exception: {str(e)}")
            return

        if response.status_code != 200:
            logger.warning(
                f"ITSM.get_soar_id() return the status code {response.status_code}"
            )
            return

        data = response.json()
        soar_id = data["request"]["udf_fields"]["udf_sline_4506"]
        logger.info(f"ITSM.get_soar_id() took: {time.time() - start} seconds")
        return soar_id

    def transform_tickets(self, data: list, integration_id: int, tenant_id: int):
        """
        Transforms raw ticket data into DuITSMFinalTickets instances.
        :param data: List of raw ticket dictionaries
        :param integration_id: Foreign key ID for the integration
        :return: List of DuITSMFinalTickets instances
        """
        start = time.time()
        logger.info(f"ITSM.transform_tickets() started : {start}")

        if not data:
            logger.warning("No ticket data to transform")
            return []

        records = []
        logger.info(
            f"Transforming tickets of ITSM for integration id: {integration_id} and tenant id: {tenant_id}"
        )
        for entry in data:
            db_id = int(entry.get("id"))
            short_description = entry.get("short_description", "")
            subject = entry.get("subject", "")
            is_overdue = entry.get("is_overdue", False)
            creation_date = entry.get("created_time", {}).get("display_value", "")
            created_by_name = entry.get("created_by", {}).get("name", "")
            account_name = entry.get("account", {}).get("name", "")
            status = entry.get("status", {}).get("name", "Unknown")

            record = DuITSMFinalTickets(
                db_id=db_id,
                short_description=short_description,
                subject=subject,
                is_overdue=is_overdue,
                creation_date=creation_date,
                created_by_name=created_by_name,
                account_name=account_name,
                itsm_tenant_id=tenant_id,
                integration_id=integration_id,
                status=status,
            )
            records.append(record)

        logger.info(f"ITSM.transform_tickets() took: {time.time() - start} seconds")
        return records

    def insert_tickets(self, tickets):
        """
        Inserts or updates DuITSMFinalTickets in the database using bulk operations.
        :param tickets: List of DuITSMFinalTickets instances
        """
        start = time.time()
        logger.info(f"ITSM.insert_tickets() started : {start}")

        if not tickets:
            logger.warning("No tickets to insert")
            return

        logger.info(f"Inserting/Updating ITSM {len(tickets)} tickets")
        try:
            with transaction.atomic():
                DuITSMFinalTickets.objects.bulk_create(
                    tickets,
                    update_conflicts=True,
                    update_fields=[
                        "short_description",
                        "subject",
                        "is_overdue",
                        "creation_date",
                        "created_by_name",
                        "account_name",
                        "itsm_tenant",
                        "integration",
                        "status",
                        "updated_at",
                    ],
                    unique_fields=["db_id"],
                )
            logger.info(
                f"Inserted/Updated {len(tickets)} tickets in {time.time() - start:.2f}s"
            )

        except Exception as e:
            logger.error(f"Failed to insert tickets: {str(e)}")

    def update_soar_ids(self, account_id: int):
        """
        Maps SOAR IDs to DuITSMFinalTickets based on db_id and updates the database.
        """
        start = time.time()
        logger.info(
            f"ITSM.update_soar_ids() started : {start} for account id: {account_id}"
        )
        # Fetch the raw data
        soar_mappings = self._get_soar_ids(account_id)

        if not soar_mappings:
            logger.warning("No SOAR mappings found.")
            return

        logger.info(f"Fetched {len(soar_mappings)} SOAR mappings")

        # Build mapping: db_id -> soar_id
        mapping_dict = {
            int(item["id"]): int(item["udf_fields"]["udf_sline_4506"])
            for item in soar_mappings
            if (
                "udf_fields" in item
                and "udf_sline_4506" in item["udf_fields"]
                and item["udf_fields"]["udf_sline_4506"] is not None
            )
        }

        if not mapping_dict:
            logger.warning("No valid mappings found with 'udf_sline_4506'.")
            return

        logger.info(f"Prepared {len(mapping_dict)} mappings for update")

        # Fetch relevant ticket entries from DB
        tickets_to_update = DuITSMFinalTickets.objects.filter(
            db_id__in=mapping_dict.keys()
        )

        updated_count = 0
        for ticket in tickets_to_update:
            new_soar_id = mapping_dict.get(ticket.db_id)
            if new_soar_id and ticket.soar_id != new_soar_id:
                ticket.soar_id = new_soar_id
                updated_count += 1

        # Bulk update
        if updated_count:
            DuITSMFinalTickets.objects.bulk_update(
                tickets_to_update, ["soar_id", "updated_at"]
            )
            logger.info(
                f"Updated {updated_count} tickets for account {account_id} with SOAR IDs in {time.time() - start:.2f}s"
            )
        else:
            logger.info("No tickets needed updating.")

    def update_soar_ids_for_tickets(self):
        """
        Updates SOAR IDs for all DuITSMFinalTickets where soar_id is NULL.
        """
        start = time.time()
        logger.info(f"ITSM.update_soar_ids() started at: {start}")

        # Step 1: Get all db_ids where soar_id is null
        ticket_ids = DuITSMFinalTickets.objects.filter(
            soar_id__isnull=True
        ).values_list("db_id", flat=True)
        logger.info(f"Found {len(ticket_ids)} tickets with null SOAR ID")

        if not ticket_ids:
            logger.info("No tickets to update.")
            return

        update_count = 0

        # Step 2: Loop through and update soar_id
        for request_id in ticket_ids:
            soar_id = self.get_soar_id(request_id)
            if soar_id is None:
                logger.warning(f"Skipping db_id={request_id}, no SOAR ID fetched")
                continue

            try:
                # Direct DB update, avoid fetching object
                DuITSMFinalTickets.objects.filter(db_id=request_id).update(
                    soar_id=soar_id
                )
                update_count += 1
                logger.info(f"Updated SOAR ID for db_id={request_id}")
            except Exception as e:
                logger.error(f"Error updating db_id={request_id}: {str(e)}")

        logger.info(f"Successfully updated {update_count} SOAR IDs")
        logger.info(f"ITSM.update_soar_ids() took: {time.time() - start} seconds")
