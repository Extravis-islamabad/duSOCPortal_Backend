import base64
import hashlib
import hmac
import time
import urllib.parse

import pandas as pd
import requests
from django.db import transaction
from loguru import logger

from common.constants import CywareConstants, SSLConstants
from common.utils import DBMappings
from tenant.models import (
    Alert,
    CywareCategories,
    CywareCustomField,
    CywareGroup,
    CywareTag,
    ThreatIntelligenceTenantAlerts,
)


class Cyware:
    def __init__(self, access_key: str, secret_key: str, base_url: str):
        """
        Initialize Cyware class.

        Args:
            access_key (str): Cyware access key.
            secret_key (str): Cyware secret key.
            base_url (str): Cyware API base URL.
        """
        self.access_key = access_key
        self.secret_key = secret_key
        self.base_url = base_url
        self.expiry = self.expiry_time()
        self.params = {
            "Expires": self.expiry,
            "AccessID": self.access_key,
            "Signature": self.signature(),
        }

    def __enter__(self):
        """
        Enter the runtime context related to this object.

        This method logs the entry into the Cyware context and
        prepares the object for use with a context manager (e.g.,
        with statement).

        :return: Returns self after logging the entry.
        """
        logger.info("Logging into Cyware")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Exit the runtime context related to this object.

        This method logs the exit from the Cyware context.

        :param exc_type: The type of exception thrown, if any.
        :param exc_value: The value of the exception thrown, if any.
        :param traceback: The traceback of the exception thrown, if any.
        """
        logger.info("Logging out of Cyware")

    def expiry_time(self) -> int:
        """
        Calculates the expiration time in seconds.

        This function returns the current time plus the expiration margin time
        in seconds.

        Returns:
            int: The expiration time in seconds.
        """
        return int(time.time() + CywareConstants.EXPIRATION_MARGIN_TIME)

    def signature(self) -> str:
        """
        Generate the signature required for authentication to Cyware.

        This function follows the exact specification as provided by Cyware.
        The signature is generated using the access key, secret key and
        the current time plus the expiration margin.

        Returns:
            str: The signature required for authentication.
        """
        to_sign = f"{self.access_key}\n{self.expiry}"
        hashed = hmac.new(self.secret_key.encode(), to_sign.encode(), hashlib.sha1)
        return base64.b64encode(hashed.digest()).decode()

    def get_alert_list(self, page: int = 1, page_size: int = 20):
        params = self.params.copy()
        params.update({"page": page, "page_size": page_size})
        url = f"{self.base_url}/api/csap/v1/list_alert/?{urllib.parse.urlencode(params, doseq=True)}"
        try:
            return requests.get(url, timeout=SSLConstants.TIMEOUT)
        except Exception as e:
            logger.error(f"Failed to fetch alerts: {str(e)}")

    def fetch_all_alerts(self, page_size=2000):
        """
        Fetch all alerts from Cyware.

        :param page_size: The number of records to fetch in each page. Defaults to 2000.
        :return: A list of all alerts
        """
        logger.info("Fetching all alerts...")
        all_alerts = []
        page = 1
        total_count = None

        while True:
            list_resp = self.get_alert_list(page=page, page_size=page_size)
            logger.info(f"\n🌐 Page {page} - Status: {list_resp.status_code}")

            try:
                list_json = list_resp.json()
            except Exception as e:
                logger.error("JSON decode failed: {}", e)
                break

            if total_count is None:
                total_count = list_json.get("count", 0)

            alert_batch = list_json.get("data", [])
            if not alert_batch:
                logger.warning("No results on this page.")
                break

            all_alerts.extend(alert_batch)

            if len(all_alerts) >= total_count:
                break

            page += 1

        logger.success("\n🌟 Total Alerts Fetched: {}\n", len(all_alerts))
        return all_alerts

    def transform_alert(self, alerts_data, integration):
        """
        Transforms the list of alert data into a list of Alert objects.

        Args:
            alerts_data (list): A list of dictionaries containing the alert data.
            integration (int): The ID of the integration for which the alerts need to be transformed.

        Returns:
            list: A list of Alert objects.
        """
        logger.info("Cyware.transform_alert() started...")
        df = pd.DataFrame(alerts_data)
        df.rename(columns={"short_id": "db_id"}, inplace=True)
        df["integration_id"] = integration
        df["published_time"] = pd.to_datetime(df["published_time"], unit="s")
        alerts = []
        for _, row in df.iterrows():
            # published_time = self.parse_datetime(row.get("published_time"))
            alert = Alert(
                db_id=row["db_id"],
                title=row.get("title", ""),
                status=row.get("status", ""),
                published_time=row["published_time"],
                integration_id=row["integration_id"],
            )
            alerts.append(alert)
        return alerts

    def transform_alert_for_tenants(self, alerts_data, threat_intel_id):
        """
        Transforms the list of alert data into a list of ThreatIntelligenceTenantAlerts objects.

        Args:
            alerts_data (list): A list of dictionaries containing the alert data.
            threat_intel_id (int): The ID of the Threat Intelligence for which the alerts need to be transformed.

        Returns:
            list: A list of ThreatIntelligenceTenantAlerts objects.
        """
        logger.info("Cyware.transform_alert() started...")
        df = pd.DataFrame(alerts_data)
        df.rename(columns={"short_id": "db_id"}, inplace=True)
        df["threat_intelligence_id"] = threat_intel_id
        df["published_time"] = pd.to_datetime(df["published_time"], unit="s")
        alerts = []
        for _, row in df.iterrows():
            # published_time = self.parse_datetime(row.get("published_time"))
            alert = ThreatIntelligenceTenantAlerts(
                db_id=row["db_id"],
                title=row.get("title", ""),
                status=row.get("status", ""),
                published_time=row["published_time"],
                threat_intelligence_id=row["threat_intelligence_id"],
            )
            alerts.append(alert)
        return alerts

    def insert_alerts(self, alerts):
        """
        Inserts/Updates alerts into the database.

        Args:
        alerts (list): A list of dictionaries representing the alerts to be inserted/updated.
        """
        start = time.time()
        logger.info(f"Cyware.insert_alerts() started : {start}")
        if not alerts:
            logger.warning("No alerts to insert")
            return
        # records = [Alert(**item) for item in alerts]
        logger.info(f"Inserting/Updating {len(alerts)} alerts")
        try:
            with transaction.atomic():
                Alert.objects.bulk_create(
                    alerts,
                    update_conflicts=True,
                    update_fields=["title", "status", "published_time", "integration"],
                    unique_fields=["db_id"],
                )
            logger.info(
                f"Inserted/Updated {len(alerts)} alerts in {time.time() - start:.2f}s"
            )

        except Exception as e:
            logger.error(f"Failed to insert alerts: {str(e)}")

    def insert_tenant_alerts(self, alerts):
        """
        Inserts/Updates alerts for a tenant into the database.

        Args:
        alerts (list): A list of dictionaries representing the alerts to be inserted/updated.
        """
        start = time.time()
        logger.info(f"Cyware.insert_tenant_alerts() started : {start}")
        if not alerts:
            logger.warning("No alerts to insert")
            return
        # records = [Alert(**item) for item in alerts]
        logger.info(f"Inserting/Updating {len(alerts)} alerts")
        try:
            with transaction.atomic():
                ThreatIntelligenceTenantAlerts.objects.bulk_create(
                    alerts,
                    update_conflicts=True,
                    update_fields=[
                        "title",
                        "status",
                        "published_time",
                    ],
                    unique_fields=["db_id"],
                )
            logger.info(
                f"Inserted/Updated {len(alerts)} alerts in {time.time() - start:.2f}s"
            )

        except Exception as e:
            logger.error(
                f"Cyware.insert_tenant_alerts() Failed to insert alerts: {str(e)}"
            )

    def get_list_groups(self) -> None:
        """
        Fetch the list of all groups (paginated).
        """
        start = time.time()
        logger.info(f"Cyware.get_list_groups() started at {start}")
        full_url = f"{self.base_url}/{CywareConstants.GROUPS_ENDPOINT}?{urllib.parse.urlencode(self.params)}"

        try:
            response = requests.get(full_url, timeout=SSLConstants.TIMEOUT)
            response.raise_for_status()
            data = response.json()
            logger.info(
                f"Cyware.get_list_groups() Completed in {time.time() - start} s"
            )
            return data
        except Exception as e:
            logger.error(f"Cyware.get_list_groups() Failed to list groups: {str(e)}")

    def transform_groups(self, data: list, integration) -> list:
        """
        Transforms raw group JSON data into CywareGroup model instances.
        """
        groups = []
        for item in data:
            group = CywareGroup(
                integration_id=integration,
                db_id=item.get("group_id"),
                group_name=item.get("group_name"),
                group_tlp=item.get("group_tlp"),
                group_type=item.get("group_type"),
                allowed_for_intel_submission=item.get(
                    "allowed_for_intel_submission", False
                ),
                allowed_for_rfi_submission=item.get(
                    "allowed_for_rfi_submission", False
                ),
            )
            groups.append(group)
        return groups

    def insert_groups(self, groups: list):
        """
        Inserts or updates CywareGroup records in the DB.
        """
        start = time.time()
        logger.info(f"Cyware.insert_groups() started : {start}")

        if not groups:
            logger.warning("No groups to insert")
            return

        logger.info(f"Inserting/Updating {len(groups)} groups")

        try:
            with transaction.atomic():
                CywareGroup.objects.bulk_create(
                    groups,
                    update_conflicts=True,
                    update_fields=[
                        "group_name",
                        "group_tlp",
                        "group_type",
                        "allowed_for_intel_submission",
                        "allowed_for_rfi_submission",
                        "updated_at",
                    ],
                    unique_fields=["db_id"],
                )
            logger.info(
                f"Inserted/Updated {len(groups)} groups in {time.time() - start:.2f}s"
            )

        except Exception as e:
            logger.error(f"Cyware.insert_groups() Failed to insert groups: {str(e)}")

    def get_list_tags(self):
        """
        Fetch the list of all tags from the Cyware API.

        This method sends an HTTP GET request to the tags endpoint of the Cyware API
        and retrieves the list of tags. It logs the start and completion time of the request.
        If the request is successful, it returns the parsed JSON response. If the request fails
        or an exception occurs, it logs an error.

        :return: A list of tags if the request is successful.
        :raises: Logs any exceptions that occur during the request.
        """

        start = time.time()
        logger.info(f"Cyware.list_tags() started : {start}")
        full_url = f"{self.base_url}/{CywareConstants.TAGS_ENDPOINT}?{urllib.parse.urlencode(self.params)}"
        try:
            response = requests.get(full_url, timeout=SSLConstants.TIMEOUT)
            response.raise_for_status()
            data = response.json()
            logger.info(f"Cyware.list_tags() Completed in {time.time() - start} s")
            return data
        except Exception as e:
            logger.error(f"Cyware.list_tags() Failed to list tags: {str(e)}")

    def transform_tags(self, data: list, integration: int) -> list:
        """
        Transforms raw tag JSON data into CywareTag model instances.
        """
        tags = []
        for item in data:
            tag = CywareTag(
                integration_id=integration,
                db_id=item.get("tag_id"),
                tag_name=item.get("tag_name"),
                tag_slug=item.get("tag_slug"),
                is_active=item.get("is_active", True),
            )
            tags.append(tag)
        return tags

    def insert_tags(self, tags: list):
        """
        Inserts or updates CywareTag records in the DB.
        """
        start = time.time()
        logger.info(f"Cyware.insert_tags() started : {start}")

        if not tags:
            logger.warning("No tags to insert")
            return

        logger.info(f"Inserting/Updating {len(tags)} tags")

        try:
            with transaction.atomic():
                CywareTag.objects.bulk_create(
                    tags,
                    update_conflicts=True,
                    update_fields=[
                        "tag_name",
                        "tag_slug",
                        "is_active",
                        "updated_at",
                    ],
                    unique_fields=["db_id"],
                )
            logger.info(
                f"Inserted/Updated {len(tags)} tags in {time.time() - start:.2f}s"
            )

        except Exception as e:
            logger.error(f"Cyware.insert_tags() Failed to insert tags: {str(e)}")

    def get_custom_fields(self):
        """
        Fetches the list of custom fields from Cyware CSAP.

        Returns:
            list: List of custom fields
        """
        start = time.time()
        logger.info(f"Cyware.get_custom_fields() started : {start}")
        full_url = f"{self.base_url}/{CywareConstants.CUSTOM_FIELDS_ENDPOINT}?{urllib.parse.urlencode(self.params)}"
        try:
            response = requests.get(full_url, timeout=SSLConstants.TIMEOUT)
            response.raise_for_status()
            data = response.json()
            logger.info(
                f"Cyware.get_custom_fields() Completed in {time.time() - start} s"
            )
            return data
        except Exception as e:
            logger.error(f"Cyware.get_custom_fields() Failed to list tags: {str(e)}")

    def transform_custom_fields(self, data: list, integration) -> list:
        """
        Transforms raw custom/system field JSON data into CustomField model instances.
        """
        fields = []
        for group in data:
            is_system = group.get("key") == "system"
            for item in group.get("values", []):
                field = CywareCustomField(
                    integration_id=integration,
                    db_id=item.get("field_id"),
                    field_name=item.get("field_name"),
                    field_label=item.get("field_label"),
                    field_type=item.get("field_type"),
                    field_description=item.get("field_description", ""),
                    is_system=is_system,
                )
                fields.append(field)
        return fields

    def insert_custom_fields(self, fields: list):
        """
        Inserts or updates CustomField records in the DB.
        """
        start = time.time()
        logger.info(f"Cyware.insert_custom_fields() started : {start}")

        if not fields:
            logger.warning("No custom fields to insert")
            return

        logger.info(f"Inserting/Updating {len(fields)} custom fields")

        try:
            with transaction.atomic():
                CywareCustomField.objects.bulk_create(
                    fields,
                    update_conflicts=True,
                    update_fields=[
                        "field_name",
                        "field_label",
                        "field_type",
                        "field_description",
                        "is_system",
                        "updated_at",
                    ],
                    unique_fields=["db_id"],
                )
            logger.info(
                f"Inserted/Updated {len(fields)} custom fields in {time.time() - start:.2f}s"
            )

        except Exception as e:
            logger.error(
                f"Cyware.insert_custom_fields() Failed to insert custom fields: {str(e)}"
            )

    def get_categories(self):
        """
        Fetches the list of all categories from Cyware CSAP.

        Returns:
            list: List of category objects
        """
        start = time.time()
        logger.info(f"Cyware.get_categories() started : {start}")
        full_url = f"{self.base_url}/{CywareConstants.CATEGORIES_ENDPOINT}?{urllib.parse.urlencode(self.params)}"
        try:
            response = requests.get(full_url, timeout=SSLConstants.TIMEOUT)
            response.raise_for_status()
            data = response.json()
            logger.info(f"Cyware.get_categories() Completed in {time.time() - start} s")
            return data["results"]
        except Exception as e:
            logger.error(f"Cyware.get_categories() Failed to list tags: {str(e)}")

    def transform_categories(self, data: list, integration) -> list:
        """
        Transforms raw category JSON data into CywareCategories model instances.
        """
        cyware_mappings = DBMappings.get_db_id_to_id_mapping(CywareCustomField)
        categories = []

        for item in data:
            category = CywareCategories(
                integration_id=integration,
                db_id=item.get("category_id"),
                category_name=item.get("category_name"),
            )

            # Collect related field IDs using db_id mapping
            def extract_field_ids(field_list):
                return [
                    cyware_mappings[field["field_id"]]
                    for field in field_list
                    if field.get("field_id") in cyware_mappings
                ]

            # Attach as temporary attributes for later use in insert step
            category._additional_fields = extract_field_ids(
                item.get("additional_fields", [])
            )
            category._threat_indicator_fields = extract_field_ids(
                item.get("threat_indicator_fields", [])
            )
            category._required_fields = extract_field_ids(
                item.get("required_fields", [])
            )

            categories.append(category)

        return categories

    def insert_categories(self, categories: list):
        """
        Inserts or updates CywareCategories and assigns M2M fields
        from pre-transformed field ID lists.
        """
        start = time.time()
        logger.info(f"Cyware.insert_categories() started : {start}")

        if not categories:
            logger.warning("No categories to insert")
            return

        logger.info(f"Inserting/Updating {len(categories)} categories")

        try:
            with transaction.atomic():
                for category in categories:
                    obj, _ = CywareCategories.objects.update_or_create(
                        db_id=category.db_id,
                        integration_id=category.integration_id,
                        defaults={
                            "category_name": category.category_name,
                        },
                    )

                    # Set M2M fields using extracted IDs
                    obj.additional_fields.set(
                        getattr(category, "_additional_fields", [])
                    )
                    obj.threat_indicator_fields.set(
                        getattr(category, "_threat_indicator_fields", [])
                    )
                    obj.required_fields.set(getattr(category, "_required_fields", []))

            logger.info(
                f"Inserted/Updated {len(categories)} categories in {time.time() - start:.2f}s"
            )

        except Exception as e:
            logger.error(f"Cyware.insert_categories() Failed: {str(e)}")
