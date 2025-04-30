import asyncio
import json

import psutil
from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from django.core.cache import cache
from loguru import logger
from rest_framework_simplejwt.tokens import AccessToken

from authentication.models import User
from common.constants import AdminWebsocketConstants


class SystemMetricsConsumer(AsyncWebsocketConsumer):
    def get_query_params(self):
        """
        Returns a dictionary of query parameters from the scope's query_string.
        For example, if the query string is "foo=bar&baz=qux", this method will
        return {"foo": "bar", "baz": "qux"}.
        """
        query_string = self.scope["query_string"].decode()
        params = dict(
            param.split("=") for param in query_string.split("&") if "=" in param
        )
        return params

    async def connect(self):
        """
        Handles the initial connection of a websocket client.

        This method authenticates the user using a JWT token extracted from the headers.
        If the user is not authenticated or not an admin, the connection is closed.
        Otherwise, the user is added to the system metrics group and the connection is accepted.
        Initial system metrics, including tenant count and resource usage, are sent to the client.
        A periodic task is started to send ongoing system metrics updates.
        """

        params = self.get_query_params()
        token = params.get("token")
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

    async def disconnect(self, close_code):
        """
        Handles the WebSocket DISCONNECT event.

        When the WebSocket connection is closed, this function is called. It
        removes the channel from the 'system_metrics_group' and cancels any
        ongoing tasks that were started to send system metrics updates.

        Args:
            close_code (int): The WebSocket close code.

        Returns:
            None
        """
        await self.channel_layer.group_discard(
            "system_metrics_group", self.channel_name
        )
        if hasattr(self, "task"):
            self.task.cancel()

    async def send_system_metrics(self):
        """
        Periodically sends system metrics to the WebSocket client.

        This function is called once when the WebSocket connection is established
        and runs indefinitely until the connection is closed. It fetches the CPU
        and memory usage, the tenant count from the cache, and sends these metrics
        to the client as a JSON object.

        If any errors occur while sending the metrics, the error is logged and the
        function waits 5 seconds before trying again.

        Args:
            None

        Returns:
            None
        """
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
                logger.error(
                    f"Error from Admin websocekt sending system metrics: {str(e)}"
                )
                await asyncio.sleep(5)

    async def tenant_count_update(self, event):
        """
        Handles the "tenant_count_update" event sent by the system.

        This event is triggered when a new tenant is created or an existing tenant is deleted.
        It sends the updated tenant count to the WebSocket client.

        Args:
            event (dict): The event from the channel layer with the updated tenant count.

        Returns:
            None
        """
        await self.send(text_data=event["message"])

    @database_sync_to_async
    def get_user_from_token(self, token):
        """
        Retrieves the User instance associated with the given JWT token.

        Args:
            token (str): The JWT token.

        Returns:
            User: The User instance associated with the token, or None if the
                token is invalid or missing.
        """
        try:
            if not token:
                return None
            access_token = AccessToken(token)
            return User.objects.get(id=access_token["user_id"])
        except Exception:
            return None
