import asyncio
import json

import psutil
from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from django.core.cache import cache
from rest_framework_simplejwt.tokens import AccessToken

from authentication.models import User
from common.constants import AdminWebsocketConstants


class SystemMetricsConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        token = self.get_token_from_headers()

        self.user = await self.get_user_from_token(token)
        if not self.user or not self.user.is_admin:
            await self.close()
            return

        await self.channel_layer.group_add(
            AdminWebsocketConstants.SYSTEM_METRICS_GROUP_NAME, self.channel_name
        )
        await self.accept()

        # Send initial tenant count on connection
        tenant_count = cache.get("tenant_count", 0)
        await self.send(
            text_data=json.dumps(
                {
                    "tenant_count": tenant_count,
                    "cpu_usage": psutil.cpu_percent(interval=1),
                    "memory_usage": psutil.virtual_memory().percent,
                    "active_chats": 0,
                    "pending_resolutions": 0,
                    "total_interactions": 0,
                    "active_integrations": 0,
                    "instance_alarm": 0,
                }
            )
        )

        # Start periodic system metrics updates
        self.task = asyncio.create_task(self.send_system_metrics())

    def get_token_from_headers(self):
        """
        Extracts the JWT token from the HTTP headers.

        Returns:
            str: The JWT token, or None if it's not present in the headers.
        """
        headers = dict(self.scope["headers"])
        auth_header = headers.get(b"authorization", b"").decode()
        if auth_header.startswith("JWT "):
            return auth_header.split("JWT ")[1]
        return None

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            "system_metrics_group", self.channel_name
        )
        if hasattr(self, "task"):
            self.task.cancel()

    async def send_system_metrics(self):
        while True:
            try:
                # Fetch CPU and memory usage
                cpu_usage = psutil.cpu_percent(interval=1)
                memory_usage = psutil.virtual_memory().percent
                tenant_count = cache.get("tenant_count", 0)

                # Send metrics to client
                await self.send(
                    text_data=json.dumps(
                        {
                            "tenant_count": tenant_count,
                            "cpu_usage": cpu_usage,
                            "memory_usage": memory_usage,
                            "active_chats": 0,
                            "pending_resolutions": 0,
                            "total_interactions": 0,
                            "active_integrations": 0,
                            "instance_alarm": 0,
                        }
                    )
                )
                await asyncio.sleep(5)  # Send updates every 5 seconds
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error in send_system_metrics: {str(e)}")
                await asyncio.sleep(5)

    async def tenant_count_update(self, event):
        # Send updated tenant count to client
        await self.send(text_data=event["message"])

    @database_sync_to_async
    def get_user_from_token(self, token):
        try:
            if not token:
                return None
            access_token = AccessToken(token)
            return User.objects.get(id=access_token["user_id"])
        except Exception:
            return None
