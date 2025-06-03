import os

from celery import Celery
from celery.schedules import crontab

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "sockportal__backend.settings")

app = Celery("sockportal__backend")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()


app.conf.beat_schedule = {
    "qradar-sync-tasks": {
        "task": "tenant.ibm_qradar_tasks.sync_ibm_qradar_data",
        "schedule": crontab(minute="*/5"),
    },
    "itsm-sync-tasks": {
        "task": "tenant.itsm_tasks.sync_itsm",
        "schedule": crontab(minute="*/5"),
    },
    "cortex-sync-tasks": {
        "task": "tenant.cortex_soar_tasks.sync_soar_data",
        "schedule": crontab(minute="*/5"),
    },
    "threat-intelligence-sync-tasks": {
        "task": "tenant.threat_intelligence_tasks.sync_threat_intel",
        "schedule": crontab(minute="*/5"),
    },
}
