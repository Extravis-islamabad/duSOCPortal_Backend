from django.db import models


class User(models.Model):
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=100, unique=True)
    is_super_admin = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)

    def __str__(self):
        return self.name

# class OrderStatus(models.IntegerChoices):
#     Awaiting_Pickup = 1
#     Picked_up = 2
#     At_QWQER_Warehouse = 3
#     On_Route_to_Delivery = 4
#     Delivered = 5
#     Attempted = 6
#     Reattempt_for_Delivery = 7
#     Cancelled = 8
