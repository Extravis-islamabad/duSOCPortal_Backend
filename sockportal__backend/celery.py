import os

from celery import Celery
from celery.schedules import crontab

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "sockportal__backend.settings")

app = Celery("sockportal__backend")

app.conf.broker_transport_options = {
    "confirm_publish": True,  # To enable publisher confirmations
    "ack_timeout": 86400000,  # Set the ack timeout in milliseconds (e.g., 1 hour)
}

app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

app.conf.task_routes = {
    "tenant.threat_intelligence_tasks.*": {"queue": "cyware"},
    "tenant.ibm_qradar_tasks.*": {"queue": "qradar"},
    "tenant.itsm_tasks.*": {"queue": "itsm"},
    "tenant.cortex_soar_tasks.*": {"queue": "soar"},
}

app.conf.beat_schedule = {
    "qradar-sync-tasks": {
        "task": "tenant.ibm_qradar_tasks.sync_ibm_qradar_data",
        "schedule": crontab(minute="*/5"),
    },
    "qradar-admin-sync-tasks": {
        "task": "tenant.ibm_qradar_tasks.sync_ibm_admin_eps",
        "schedule": crontab(
            minute="0"
        ),  # Run at the whenever the minute will 0 of any hour means running it every hour
    },
    "qradar-tenant-sync-tasks": {
        "task": "tenant.ibm_qradar_tasks.sync_ibm_tenant_eps",
        "schedule": crontab(
            minute="*/5"
        ),  # Run at the whenever the minute will 5 of any hour means running it every hour
    },
    "qradar-daily-sync-tasks": {
        "task": "tenant.ibm_qradar_tasks.sync_ibm_tenant_daily_eps",
        "schedule": crontab(minute="30", hour="1"),  # Run at 1:30 AM every day
    },
    # "qradar-tenant-daily-sync-tasks": {
    #     "task": "tenant.ibm_qradar_tasks.sync_ibm_qradar_daily_sync",
    #     "schedule": crontab(minute="55", hour="23"),  # Run at 11:55 PM every day
    # },
    "itsm-sync-tasks": {
        "task": "tenant.itsm_tasks.sync_itsm",
        "schedule": crontab(minute="*/5"),
    },
    "cortex-sync-tasks": {
        "task": "tenant.cortex_soar_tasks.sync_soar_data",
        "schedule": crontab(minute="*/5"),
    },
    # "threat-intelligence-sync-tasks": {
    #     "task": "tenant.threat_intelligence_tasks.default_cyware",
    #     "schedule": crontab(minute="*/5"),
    #     "options": {"queue": "cyware"},
    # },
    # "threat-intelligence-tenant-sync-tasks": {
    #     "task": "tenant.threat_intelligence_tasks.custom_cyware",
    #     "schedule": crontab(minute="*/5"),
    #     "options": {"queue": "cyware"},
    # },
    # "threat-intelligence-all-sync-tasks": {
    #     "task": "tenant.threat_intelligence_tasks.sync_threat_intel_all",
    #     "schedule": crontab(minute="*/30"),
    #     "options": {"queue": "cyware"},
    # },
}
