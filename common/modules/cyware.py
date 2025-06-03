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
from tenant.models import Alert, ThreatIntelligenceTenantAlerts


class Cyware:
    def __init__(self, access_key: str, secret_key: str, base_url: str):
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
        logger.info("Logging into Cyware")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        logger.info("Logging out of Cyware")

    def expiry_time(self) -> int:
        return int(time.time() + CywareConstants.EXPIRATION_MARGIN_TIME)

    def signature(self) -> str:
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
