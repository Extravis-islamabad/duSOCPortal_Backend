import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "sockportal__backend.settings")

app = Celery("sockportal__backend")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
