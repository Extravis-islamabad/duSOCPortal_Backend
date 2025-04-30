from django.urls import re_path

from . import consumers

websocket_urlpatterns = [
    re_path(r"ws/admin/$", consumers.SystemMetricsConsumer.as_asgi()),
]
