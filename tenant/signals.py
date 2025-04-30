import json

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.core.cache import cache
from django.db.models.signals import post_save
from django.dispatch import receiver
from loguru import logger

from common.constants import AdminWebsocketConstants
from tenant.models import Tenant


@receiver(post_save, sender=Tenant)
def tenant_created(sender, instance, created, **kwargs):
    """
    Signal receiver that is triggered when a Tenant instance is created.

    This function increments the tenant count stored in cache and broadcasts
    the updated tenant count to WebSocket clients in the 'tenant_count_group'.

    Args:
        sender (Model): The model class that sent the signal.
        instance (Tenant): The actual instance being saved.
        created (bool): Boolean indicating if a new record was created.
        **kwargs: Additional keyword arguments.
    """

    if created:
        logger.info("signals.py.tenant_created setting the cache")
        tenant_count = cache.get("tenant_count", 0)
        tenant_count += 1
        cache.set("tenant_count", tenant_count, timeout=None)

        logger.info("signals.py.tenant_created broadcasting tenant_count_update")
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            AdminWebsocketConstants.SYSTEM_METRICS_GROUP_NAME,
            {
                "type": "tenant_count_update",
                "message": json.dumps({"tenant_count": tenant_count}),
            },
        )
