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

# Task retry configuration
app.conf.task_annotations = {
    "*": {
        "max_retries": 2,
        "default_retry_delay": 60,  # 60 seconds between retries
    }
}

# Optional: Set specific retry policies for different task types
app.conf.task_default_max_retries = 2
app.conf.task_default_retry_delay = 60

# Task time limits
app.conf.task_soft_time_limit = 3600  # 1 hour soft limit (raises SoftTimeLimitExceeded)
app.conf.task_time_limit = 3700  # 1 hour + 100 seconds hard limit (task is killed)

# Track failed tasks
app.conf.task_track_started = True
app.conf.task_send_sent_event = True
app.conf.result_expires = 3600  # Results expire after 1 hour

app.conf.beat_schedule = {
    "qradar-sync-tasks": {
        "task": "tenant.ibm_qradar_tasks.sync_ibm_qradar_data",
        "schedule": crontab(minute="*/5"),
        "options": {"queue": "qradar"},
    },
    "qradar-admin-sync-tasks": {
        "task": "tenant.ibm_qradar_tasks.sync_ibm_admin_eps",
        "schedule": crontab(
            minute="0"
        ),  # Run at the whenever the minute will 0 of any hour means running it every hour
        "options": {"queue": "qradar"},
    },
    "qradar-tenant-sync-tasks": {
        "task": "tenant.ibm_qradar_tasks.sync_ibm_tenant_eps",
        "schedule": crontab(
            minute="*/5"
        ),  # Run at the whenever the minute will 5 of any hour means running it every hour
        "options": {"queue": "qradar"},
    },
    "qradar-daily-sync-tasks": {
        "task": "tenant.ibm_qradar_tasks.sync_ibm_tenant_daily_eps",
        "schedule": crontab(minute="30", hour="1"),  # Run at 1:30 AM every day
        "options": {"queue": "qradar"},
    },
    # "qradar-tenant-daily-sync-tasks": {
    #     "task": "tenant.ibm_qradar_tasks.sync_ibm_qradar_daily_sync",
    #     "schedule": crontab(minute="55", hour="23"),  # Run at 11:55 PM every day
    # },
    "itsm-sync-tasks": {
        "task": "tenant.itsm_tasks.sync_itsm",
        "schedule": crontab(minute="*/5"),
        "options": {"queue": "itsm"},
    },
    "cortex-sync-tasks": {
        "task": "tenant.cortex_soar_tasks.sync_soar_data",
        "schedule": crontab(minute="*/5"),
        "options": {"queue": "soar"},
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
