import json
import os
import time

import pandas as pd
import pytz
import requests
from django.db import transaction
from django.utils.dateparse import parse_datetime

DUBAI_TZ = pytz.timezone("Asia/Dubai")
from loguru import logger

from common.constants import CortexSOARConstants, EnvConstants, SSLConstants
from tenant.models import (
    DUCortexSOARIncidentFinalModel,
    DuCortexSOARTenants,
    DUSoarNotes,
)


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

    def _get_accounts(self, timeout=SSLConstants.TIMEOUT):
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
                timeout=timeout,
            )
        except Exception as e:
            logger.error(f"CortexSOAR._get_accounts() failed with exception : {str(e)}")
            return
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

    def _get_incidents(
        self,
        account_name: str,
        day_week_month: str,
        batch_size=CortexSOARConstants.BATCH_SIZE,
    ):
        """
        Fetches the list of incidents from the CortexSOAR instance.

        :return: A list of incidents.
        """
        start = time.time()
        logger.info(f"CortexSOAR._get_incidents() started : {start}")
        logger.info(
            f"CortexSOAR._get_incidents() fetching data for : {account_name} for {day_week_month}"
        )
        endpoint = f"{self.base_url}/{CortexSOARConstants.INCIDENT_ENDPOINT}"
        body = {
            "userFilter": False,
            "filter": {
                "page": 0,
                "size": batch_size,
                "query": "",
                "sort": [{"field": "id", "asc": False}],
                "accounts": {account_name: {}},
                "period": {"by": day_week_month, "fromValue": None},
            },
        }
        # body = {
        #     "userFilter": False,
        #     "filter": {
        #         "page": 0,
        #         "size": batch_size,
        #         "query": "",
        #         "sort": [{"field": "id", "asc": False}],
        #         "accounts": {account_name: {}},
        #         "period": {"by": day_week_month, "fromValue": None},
        #     },
        # }
        try:
            response = requests.post(
                endpoint,
                headers=self.headers,
                json=body,
                verify=SSLConstants.VERIFY,
                timeout=SSLConstants.TIMEOUT,
            )
        except Exception as e:
            logger.error(
                f"CortexSOAR._get_incidents() failed with exception : {str(e)}"
            )
            return
        if response.status_code != 200:
            logger.warning(
                f"CortexSOAR._get_incidents() return the status code {response.status_code}"
            )
            return

        data = response.json()
        return data

    def safe_parse_datetime(self, value):
        """
        Safely parses a datetime string into a datetime object.

        :param value: The value to parse, expected to be a string.
        :return: A datetime object if the value is a valid datetime string, otherwise None.
        """

        if isinstance(value, str):
            return parse_datetime(value)
        return None

    def extract_digits(self, value):
        """
        Extracts the first sequence of digits found in the input value.

        :param value: A string potentially containing digits.
        :return: An integer representing the first sequence of digits found, or None if no digits are present.
        """

        c = value.split(" ")
        return int(c[-1])

    def _transform_incidents(self, data, integration_id, cortex_tenant):
        """
        Transforms the CortexSOAR data into a format suitable for
        insertion into the database with proper validation checks.

        :param data: The CortexSOAR data.
        :param integration_id: The ID of the integration.
        :param cortex_tenant: The CortexSOAR tenant.
        :return: A list of DUCortexSOARIncidentFinalModel instances.
        """
        data = data.get("data", None)

        if data is None:
            logger.warning(
                f"No data found for the CortexSOAR tenant : {cortex_tenant.name}"
            )
            return
        records = []

        for entry in data:
            custom = entry.get("CustomFields", {})
            investigation_id = entry.get("investigationId")
            owner = entry.get("owner")

            # Parse time fields and validate them
            incident_tta = self.safe_parse_datetime(custom.get("incidenttta"))
            incident_ttdn = self.safe_parse_datetime(custom.get("incidentttdn"))
            incident_ttn = self.safe_parse_datetime(custom.get("incidentttn"))

            if incident_tta is None or incident_ttdn is None or incident_ttn is None:
                continue

            itsmsyncstatus = custom.get("itsmsyncstatus")
            if itsmsyncstatus in ("", " ", None):
                itsmsyncstatus = None
            else:
                itsmsyncstatus = str(itsmsyncstatus).strip()

            # Create the record
            record = DUCortexSOARIncidentFinalModel(
                db_id=self.extract_digits(entry.get("id")),
                created=self.safe_parse_datetime(entry.get("created")),
                modified=self.safe_parse_datetime(entry.get("modified")),
                account=entry.get("account"),
                name=entry.get("name"),
                status=entry.get("status"),
                reason=entry.get("qradarclosereason"),
                occured=self.safe_parse_datetime(entry.get("occurred")),
                closed=self.safe_parse_datetime(entry.get("closed")),
                sla=entry.get("sla"),
                severity=entry.get("severity"),
                investigated_id=investigation_id,
                closing_user_id=entry.get("closingUserId"),
                owner=owner,
                playbook_id=entry.get("playbookId"),
                incident_phase=custom.get("incidentphase"),
                incident_priority=custom.get("incidentpriority"),
                incident_tta=incident_tta,
                incident_ttdn=incident_ttdn,
                incident_ttn=incident_ttn,
                initial_notification=custom.get("initialnotification"),
                list_of_rules_offense=custom.get("listofrulesoffense"),
                log_source_type=custom.get("logsourcetype"),
                low_level_categories_events=custom.get("lowlevelcategoriesevents"),
                qradar_category=custom.get("qradarcategory"),
                qradar_sub_category=custom.get("qradarsubcategory"),
                source_ips=custom.get("sourceips"),
                tta_calculation=custom.get("ttacalculation"),
                integration=integration_id,
                cortex_soar_tenant=cortex_tenant,
                itsm_sync_status=itsmsyncstatus,
            )
            records.append(record)
        return records

    def _insert_incidents(self, records):
        """
        Inserts or updates the incidents in the DUCortexSOARIncidentFinalModel table.

        :param records: A list of dictionaries containing incident information.
        """
        start = time.time()
        if not records:
            return
        logger.info(f"CortexSOAR._insert_incidents() started : {start}")
        logger.info(f"Inserting the incidents records: {len(records)}")
        try:
            with transaction.atomic():
                DUCortexSOARIncidentFinalModel.objects.bulk_create(
                    records,
                    update_conflicts=True,
                    update_fields=[
                        "created",
                        "modified",
                        "name",
                        "status",
                        "reason",
                        "occured",
                        "closed",
                        "sla",
                        "severity",
                        "investigated_id",
                        "closing_user_id",
                        "owner",
                        "playbook_id",
                        "incident_phase",
                        "incident_priority",
                        "incident_tta",
                        "incident_ttdn",
                        "incident_ttn",
                        "initial_notification",
                        "list_of_rules_offense",
                        "log_source_type",
                        "low_level_categories_events",
                        "source_ips",
                        "qradar_category",
                        "itsm_sync_status",
                        "qradar_sub_category",
                        "tta_calculation",
                        "integration",
                        "cortex_soar_tenant",
                    ],
                    unique_fields=["account", "db_id"],
                )
            logger.info(f"Inserted the incidents records: {len(records)}")
            logger.success(
                f"CortexSOAR._insert_incidents() took: {time.time() - start} seconds"
            )
        except Exception as e:
            logger.error(
                f"An error occurred in CortexSOAR._insert_incidents(): {str(e)}"
            )
            transaction.rollback()

    # def fetch_investigation_details():
    #     endpoint = "https://10.225.148.130/acc_CDC-Mey-Tabreed/investigation/8208"
    #     headers = {
    #         "Accept": "application/json",
    #         "Authorization": "177EED5CCA3878582CEFCA88F7DC9759",
    #         "Content-Type": "application/json"
    #     }
    #     payload = {
    #         "userFilter": False
    #     }

    #     try:
    #         response = requests.post(endpoint, headers=headers, json=payload, verify=False)
    #         response.raise_for_status()
    #         return response.json()
    #     except requests.exceptions.RequestException as e:
    #         print("Error during request:", str(e))
    #         return None

    def _get_notes(self, account_name, incident_id, timeout=SSLConstants.TIMEOUT):
        """
        Fetches the list of notes from the CortexSOAR instance for a given incident.

        :param account_name: The name of the account.
        :param incident_id: The ID of the incident.
        :param timeout: The timeout for the request in seconds.
        :return: A list of notes if the request is successful, otherwise an empty list.
        :raises: Logs any exceptions that occur during the request.
        """
        start = time.time()
        logger.info(f"CortexSOAR._get_notes() started : {start}")
        payload = {"userFilter": False}
        endpoint = f"{self.base_url}/{account_name}/{CortexSOARConstants.NOTES_ENDPOINT}/{incident_id}"
        try:
            if EnvConstants.LOCAL:
                proxies = {
                    "http": "http://127.0.0.1:8080",
                    "https": "http://127.0.0.1:8080",
                }
                response = requests.post(
                    endpoint,
                    headers=self.headers,
                    json=payload,
                    verify=SSLConstants.VERIFY,
                    proxies=proxies,
                    timeout=timeout,
                )
            else:
                response = requests.post(
                    endpoint,
                    headers=self.headers,
                    json=payload,
                    verify=SSLConstants.VERIFY,
                    timeout=timeout,
                )

        except Exception as e:
            logger.error(f"CortexSOAR._get_notes() failed with exception : {str(e)}")
            return
        if response.status_code != 200:
            logger.warning(
                f"CortexSOAR._get_notes() return the status code {response.status_code}"
            )
            return

        data = response.json()
        return data

    def _transform_notes_data(
        self, entries: list, incident_id, integration_id, account
    ) -> list:
        """
        Transforms raw note entries into a list of DUSoarNotes model instances.
        Skips entries with empty user.
        """
        logger.info(f"CortexSOAR._transform_notes_data() incident_id: {incident_id}")
        records = []
        entries = entries.get("entries")
        for rec in entries:
            if not rec.get("user"):
                continue

            try:
                db_id_str = rec.get("id", "").split("@")[0]
                db_id = int(db_id_str)
            except (IndexError, ValueError):
                continue  # Skip malformed db_id

            records.append(
                DUSoarNotes(
                    db_id=db_id,
                    category=rec.get("category"),
                    content=rec.get("contents"),
                    created=parse_datetime(rec.get("created")),
                    user=rec.get("user"),
                    incident_id=incident_id,
                    integration_id=integration_id,
                    account=account,
                )
            )

        return records

    def _insert_notes(self, records: list):
        """
        Inserts or updates notes records in the DUSoarNotes table.

        :param records: A list of DUSoarNotes model instances.
        """
        start = time.time()
        logger.info(f"CortexSOAR._insert_notes() started : {start}")

        try:
            with transaction.atomic():
                DUSoarNotes.objects.bulk_create(
                    records,
                    update_conflicts=True,
                    update_fields=[
                        "category",
                        "content",
                        "created",
                        "user",
                        "incident_id",
                        "integration_id",
                        "updated_at",
                    ],
                    unique_fields=["db_id", "account", "user"],
                )
            logger.success(
                f"CortexSOAR._insert_notes() took: {time.time() - start:.2f} seconds"
            )
        except Exception as e:
            logger.error(f"An error occurred in CortexSOAR._insert_notes(): {str(e)}")
            transaction.set_rollback(True)
