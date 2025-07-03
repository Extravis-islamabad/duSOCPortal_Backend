# chat/consumers.py

import json
from urllib.parse import parse_qs

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from loguru import logger
from rest_framework_simplejwt.tokens import AccessToken

from authentication.models import User
from tenant.models import ChatMessage, Tenant


class AdminTenantChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_group_name = None
        self.params = parse_qs(self.scope["query_string"].decode())
        self.token = self.params.get("token", [None])[0]
        self.user = await self.get_user_from_token(self.token)

        if not self.user:
            await self.close()
            return

        self.admin_id = self.scope["url_route"]["kwargs"]["admin_id"]
        self.tenant_id = self.scope["url_route"]["kwargs"]["tenant_id"]

        if self.user.is_admin and str(self.user.id) != self.admin_id:
            await self.close()
            return

        elif self.user.is_tenant:
            tenant_obj = await self.get_tenant_object(self.tenant_id)
            if not tenant_obj:
                # await self.send(text_data=json.dumps({
                #     "error": True,
                #     "message": f"Tenant with ID {self.tenant_id} does not exist."
                # }))
                await self.close()
                return

            if tenant_obj.tenant_id != self.user.id:
                # await self.send(text_data=json.dumps({
                #     "error": True,
                #     "message": "You are not authorized to access this tenant's chat."
                # }))
                await self.close()
                return

            self.tenant = tenant_obj  # Optional c

        self.room_group_name = f"chat_{self.admin_id}_{self.tenant_id}"

        await self.channel_layer.group_add(self.room_group_name, self.channel_name)

        await self.accept()
        history = await self.get_chat_history()
        for msg in history:
            await self.send(
                text_data=json.dumps(
                    {
                        "message": msg["message"],
                        "sender": msg["sender"],
                        "timestamp": msg["timestamp"],
                    }
                )
            )

    async def disconnect(self, close_code):
        if self.room_group_name:
            await self.channel_layer.group_discard(
                self.room_group_name, self.channel_name
            )

    async def chat_message(self, event):
        await self.send(
            text_data=json.dumps(
                {"message": event["message"], "sender": event["sender"]}
            )
        )

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            msg_type = data.get("type", "message")

            if msg_type == "message":
                message = data["message"]
                await self.save_message(message)

                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        "type": "chat_message",
                        "message": message,
                        "sender": self.user.username,
                    },
                )

            elif msg_type == "load_more":
                offset = int(data.get("offset", 0))
                history = await self.get_chat_history(offset=offset)
                await self.send(
                    text_data=json.dumps({"type": "history", "messages": history})
                )
        except (json.JSONDecodeError, KeyError):
            await self.send(
                text_data=json.dumps({"error": True, "message": "Invalid format."})
            )

    @database_sync_to_async
    def get_user_from_token(self, token):
        try:
            if not token:
                return None
            access_token = AccessToken(token)
            return User.objects.get(id=access_token["user_id"])
        except Exception:
            return None

    @database_sync_to_async
    def save_message(self, message):
        try:
            tenant = Tenant.objects.get(id=self.tenant_id)
            admin = User.objects.get(id=self.admin_id)
            ChatMessage.objects.create(
                sender=self.user, admin=admin, tenant=tenant, message=message
            )
        except Exception as e:
            logger.error(f"Failed to save message: {str(e)}")

    @database_sync_to_async
    def get_chat_history(self, offset=0, limit=50):
        try:
            tenant = Tenant.objects.get(id=self.tenant_id)
            messages = (
                ChatMessage.objects.filter(admin__id=self.admin_id, tenant=tenant)
                .order_by("-timestamp")[offset : offset + limit]
                .values("message", "sender__username", "timestamp")
            )
            return [
                {
                    "message": m["message"],
                    "sender": m["sender__username"],
                    "timestamp": m["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                }
                for m in reversed(messages)
            ]
        except Exception as e:
            logger.error(f"Failed to get chat history: {str(e)}")
            return []

    @database_sync_to_async
    def get_tenant_object(self, tenant_id):
        try:
            return Tenant.objects.get(id=tenant_id)
        except Tenant.DoesNotExist:
            return None
