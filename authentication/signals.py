# signals.py
from django.contrib.auth.models import (
    User as DjangoUser,  # Import the Django User model
)
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import User  # Import your custom User model


@receiver(post_save, sender=DjangoUser)
def create_custom_user(sender, instance, created, **kwargs):
    """
    This function automatically creates a corresponding User object in the custom User model
    whenever a new Django user is created.
    """
    if created:
        # Create the custom user object with the desired fields
        User.objects.create(
            name=instance.first_name,  # Assuming you want to use the first name from the Django User
            email=instance.email,
            username=instance.username,
            is_admin=False,  # Default to False, adjust as necessary
            is_super_admin=False,  # Default to False, adjust as necessary
        )
