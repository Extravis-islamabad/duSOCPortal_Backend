from django.db import models

from authentication.models import User

# Create your models here.


# Tenant Model
class Tenant(models.Model):
    created_by = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="created_tenants"
    )
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name
