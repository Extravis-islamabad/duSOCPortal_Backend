from django.urls import re_path

from . import chat_consumers, consumers

websocket_urlpatterns = [
    re_path(r"ws/admin/$", consumers.SystemMetricsConsumer.as_asgi()),
    re_path(
        r"ws/chat/(?P<admin_id>\d+)/(?P<tenant_id>\d+)/$",
        chat_consumers.AdminTenantChatConsumer.as_asgi(),
    ),
]
