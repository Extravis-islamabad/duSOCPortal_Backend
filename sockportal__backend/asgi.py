"""
ASGI config for sockportal__backend project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/
"""

import os

import django
from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter

# Set the settings module and initialize Django before importing anything else
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "sockportal__backend.settings")
django.setup()

# Now import the application and routing modules
from django.core.asgi import get_asgi_application

from tenant.routing import websocket_urlpatterns

django_application = get_asgi_application()

application = ProtocolTypeRouter(
    {
        "http": django_application,
        "websocket": AuthMiddlewareStack(URLRouter(websocket_urlpatterns)),
    }
)
