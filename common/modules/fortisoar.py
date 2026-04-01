import time
from datetime import datetime
from urllib.parse import parse_qs, urlparse

import pandas as pd
import requests
from django.db import transaction
from loguru import logger

from common.constants import EnvConstants, FortiSOARConstants, SSLConstants
from tenant.models import DUFortiSOARIncidentModel, DUFortiSOARTenants


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
        """
        Returns the base URL of the FortiSOAR instance.

        If the port number of the FortiSOAR instance is not 80, it returns the base URL in the format
        https://{ip_address}:{port}. Otherwise, it returns the base URL in the format https://{ip_address}.

        :return: The base URL of the FortiSOAR instance.
        """
        if self.port != 80:
            return f"https://{self.ip_address}:{self.port}"
        return f"https://{self.ip_address}"

    def safe_parse_datetime(self, value):
        """
        Safely parses a datetime string into a datetime object.

        This method takes a value which is expected to be a valid datetime string and
        attempts to parse it into a datetime object. If the value is not a valid
        datetime string, it catches the exception and returns None.

        :param value: The value to parse, expected to be a valid datetime string.
        :return: A datetime object if the value is a valid datetime string, otherwise None.
        """
        try:
            dt = datetime.fromtimestamp(value)
            return dt.replace(microsecond=0).isoformat()
        except Exception:
            return None

    def safe_parse_event_time(self, value):
        """
        Safely parses FortiSOAR eventTime values into a normalized string.

        Supports multiple input formats (12h/24h, optional seconds, optional AM/PM).
        Returns a string formatted as "%Y-%m-%d %H:%M:%S" or None if parsing fails.
        """
        if value in ("", " ", None):
            return None

        if isinstance(value, (int, float)):
            try:
                dt = datetime.fromtimestamp(value)
                return dt.replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                return None

        if isinstance(value, datetime):
            return value.replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")

        if not isinstance(value, str):
            return None

        raw = value.strip()
        if not raw:
            return None

        candidates = [raw]
        parts = raw.split()
        if len(parts) >= 2 and parts[-1].upper() in ("AM", "PM"):
            candidates.append(" ".join(parts[:-1]))

        formats = [
            "%m/%d/%Y %I:%M %p",
            "%m/%d/%Y %I:%M:%S %p",
            "%m/%d/%Y %H:%M %p",
            "%m/%d/%Y %H:%M:%S %p",
            "%m/%d/%Y %H:%M",
            "%m/%d/%Y %H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
        ]

        for candidate in candidates:
            for fmt in formats:
                try:
                    dt = datetime.strptime(candidate, fmt)
                    return dt.replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")
                except ValueError:
                    continue

        return None

    def safe_parse_int(self, value):
        """
        Safely parses integer-like values into an int.

        Returns None for blank, whitespace-only, or invalid values.
        """
        if value in ("", " ", None):
            return None

        if isinstance(value, bool):
            return int(value)

        if isinstance(value, (int, float)):
            return int(value)

        if isinstance(value, str):
            value = value.strip()
            if not value:
                return None

        try:
            return int(value)
        except (TypeError, ValueError):
            return None

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
        base_endpoint = f"{self.base_url}/{FortiSOARConstants.ALERTS_ENDPOINT}"
        page = 1
        limit = FortiSOARConstants.LIMIT
        last_page = None
        all_alerts = []

        while True:
            params = {"tenant__name": tenant_name, "$page": page, "$limit": limit}
            try:
                if EnvConstants.LOCAL:
                    proxies = {
                        "http": "http://127.0.0.1:8080",
                        "https": "http://127.0.0.1:8080",
                    }
                    response = requests.get(
                        base_endpoint,
                        params=params,
                        headers=self.headers,
                        verify=SSLConstants.VERIFY,
                        proxies=proxies,
                        timeout=timeout,
                    )
                else:
                    response = requests.get(
                        base_endpoint,
                        params=params,
                        headers=self.headers,
                        verify=SSLConstants.VERIFY,
                        timeout=timeout,
                    )
            except Exception as e:
                logger.error(
                    f"FortiSOAR._get_alerts() failed with exception : {str(e)} on page {page}"
                )
                raise Exception(
                    f"FortiSOAR._get_alerts() failed with exception : {str(e)}"
                )

            if response.status_code != 200:
                logger.warning(
                    f"FortiSOAR._get_alerts() returned status code {response.status_code} on page {page}"
                )
                raise Exception(
                    f"FortiSOAR._get_alerts() return the status code {response.status_code}"
                )

            data = response.json()
            page_alerts = data.get("hydra:member", [])
            all_alerts.extend(page_alerts)

            # Determine last page from hydra:view metadata if available
            view = data.get("hydra:view") or {}
            if last_page is None and view.get("hydra:last"):
                parsed = urlparse(view.get("hydra:last"))
                qs = parse_qs(parsed.query)
                last_page_param = qs.get("$page") or qs.get("%24page")
                if last_page_param:
                    try:
                        last_page = int(last_page_param[0])
                    except (TypeError, ValueError):
                        last_page = None

            logger.debug(
                f"FortiSOAR._get_alerts() fetched page {page} with {len(page_alerts)} alerts"
            )

            if last_page is not None and page >= last_page:
                break
            if not page_alerts:
                break

            page += 1

        logger.info(
            f"FortiSOAR._get_alerts() collected {len(all_alerts)} alerts across {page} pages for {tenant_name}"
        )

        # Return in the same structure expected by downstream consumers
        return all_alerts

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
        df = df[df["name"].str.lower() != "self"]
        df["integration_id"] = integration_id
        results = df.to_dict(orient="records")
        return results

    def transform_alerts(self, data, integration_id, forti_soar_tenant_id, name):
        """
        Transforms the list of alerts from the FortiSOAR API response into a list of dictionaries.

        :param data: A dictionary containing the FortiSOAR API response.
        :param integration_id: The integration ID to be associated with the alerts.
        :return: A list of dictionaries containing the transformed alert information.
        """

        alerts_data = data
        if not alerts_data:
            logger.warning("No alerts found in FortiSOAR API response")
            return []

        records = []
        for alert in alerts_data:
            # Handle iTSMSyncStatus with safe nested access
            itsm_sync_obj = alert.get("iTSMSyncStatus")
            itsmsyncstatus = itsm_sync_obj.get("itemValue") if itsm_sync_obj else None
            if itsmsyncstatus in ("", " ", None):
                itsmsyncstatus = None
            else:
                itsmsyncstatus = str(itsmsyncstatus).strip()

            incident_tta = self.safe_parse_datetime(alert.get("incidentTTA"))
            incident_ttn = self.safe_parse_datetime(alert.get("incidentTTN"))
            incident_ttdn = self.safe_parse_datetime(alert.get("incidentTTDN"))

            if incident_tta is None or incident_ttn is None or incident_ttdn is None:
                continue

            status_obj = alert.get("status")
            severity_obj = alert.get("severity")
            priority_obj = alert.get("incidentPriority")
            phase_obj = alert.get("incidentPhase")
            closing_user_obj = alert.get("sOCGroup")
            initial_notification_obj = alert.get("initialNotification")
            initial_notification_value = (
                initial_notification_obj.get("itemValue")
                if initial_notification_obj
                else None
            )
            event_time = alert.get("eventTime")
            owner_obj = alert.get("assignedTo")
            owner_fist_name = owner_obj.get("firstname") if owner_obj else None
            owner_last_name = owner_obj.get("lastname") if owner_obj else None
            if owner_fist_name and owner_last_name:
                owner = owner_fist_name + " " + owner_last_name
            else:
                owner = None

            priority_value = priority_obj.get("itemValue") if priority_obj else None
            priority_map = {
                "P1": "P1 Critical",
                "P2": "P2 High",
                "P3": "P3 Medium",
                "P4": "P4 Low",
            }
            mapped_priority = priority_map.get(priority_value, priority_value)

            record = DUFortiSOARIncidentModel(
                db_id=self.safe_parse_int(alert.get("id")),
                created=self.safe_parse_datetime(alert.get("createDate")),
                modified=self.safe_parse_datetime(alert.get("modifyDate")),
                account=name,
                name=alert.get("name"),
                status=status_obj.get("itemValue") if status_obj else None,
                # record["status_value"] = status_obj.get("orderIndex") if status_obj else None
                reason=alert.get("qradarCloseReason"),
                occured=self.safe_parse_event_time(event_time),
                closed=self.safe_parse_datetime(alert.get("resolveddate")),
                owner=owner,
                severity=severity_obj.get("orderIndex") if severity_obj else None,
                # record["severity_text"] = severity_obj.get("itemValue") if severity_obj else None
                tta_calculation=alert.get("tTACalculation"),
                incident_priority=mapped_priority,
                incident_phase=phase_obj.get("itemValue") if phase_obj else None,
                source_ips=alert.get("sourceIp"),
                incident_tta=incident_tta,
                incident_ttn=incident_ttn,
                incident_ttdn=incident_ttdn,
                closing_user_id=closing_user_obj.get("itemValue")
                if closing_user_obj
                else None,
                initial_notification=True
                if initial_notification_value == "Yes"
                else None,
                list_of_rules_offense=alert.get("listOfRulesOffense"),
                configuration_item=alert.get("logSourceName"),
                log_source_type=alert.get("logSourceType"),
                qradar_category=alert.get("qRadarCategory"),
                qradar_sub_category=alert.get("qRadarSubCategory"),
                itsm_sync_status=itsmsyncstatus,
                mitre_tactic=alert.get("mitreTactic"),
                mitre_technique=alert.get("mitreTechnique"),
                close_notes=alert.get("closureNotes"),
                integration_id=integration_id,
                forti_soar_tenant_id=forti_soar_tenant_id,
                analysis_notes=alert.get("analysisNotes"),
                offense_id=self.safe_parse_int(alert.get("offenseID")),
                ticket_id=self.safe_parse_int(alert.get("iTSMID")),
            )

            records.append(record)
        return records

    def _insert_tenants(self, accounts: dict):
        """
        Inserts or updates tenant records in the FortiSOARTenants table.

        :param accounts: A list of dictionaries containing tenant information.
        """
        start = time.time()
        logger.info(f"FortiSOAR._insert_accounts() started : {start}")
        records = [DUFortiSOARTenants(**item) for item in accounts]
        logger.info(f"Inserting the accounts records: {len(records)}")
        try:
            with transaction.atomic():
                DUFortiSOARTenants.objects.bulk_create(
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

    def _insert_alerts(self, records: list):
        """
        Inserts or updates incident records in the DUFortiSOARIncidentModel table.

        :param records: A list of DUFortiSOARIncidentModel instances to insert/update.
        """
        start = time.time()
        logger.info(f"FortiSOAR._insert_incidents() started : {start}")
        logger.info(f"Inserting the incident records: {len(records)}")

        try:
            with transaction.atomic():
                DUFortiSOARIncidentModel.objects.bulk_create(
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
                        "forti_soar_tenant",
                        "mitre_tactic",
                        "mitre_technique",
                        "configuration_item",
                        "close_notes",
                        "analysis_notes",
                        "offense_id",
                        "ticket_id",
                    ],
                    unique_fields=["account", "db_id", "integration"],
                )
                logger.info(f"Inserted the incident records: {len(records)}")
                logger.success(
                    f"FortiSOAR._insert_incidents() took: {time.time() - start} seconds"
                )
        except Exception as e:
            logger.error(
                f"An error occurred in FortiSOAR._insert_incidents(): {str(e)}"
            )
            transaction.rollback()
            raise Exception(
                f"An error occurred in FortiSOAR._insert_incidents(): {str(e)}"
            )
