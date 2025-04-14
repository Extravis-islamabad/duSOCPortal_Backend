from django.db import models

from authentication.models import User
from common.utils import PasswordCreation

# Create your models here.


# Tenant Model
class Tenant(models.Model):
    created_by = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="created_tenants"
    )
    name = models.CharField(
        max_length=255, default=None, null=True, blank=True, unique=True
    )
    password = models.CharField(max_length=255, null=True, blank=True)
    email = models.EmailField(null=True, blank=True, unique=True)
    phone_number = models.CharField(max_length=20, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def set_password(self, raw_password):
        self.hashed_password = PasswordCreation._make_password(raw_password)

    def check_password(self, raw_password):
        return PasswordCreation._check_password(raw_password, self.hashed_password)


class TenantPermissionChoices(models.IntegerChoices):
    DASHBOARD = 1, "Dashboard"
    CHATBOT = 2, "Chatbot"
    REPORTS = 3, "Reports"
    THREAT_INTELLIGENCE = 4, "Threat Intelligence"
    ASSETS = 5, "Assets"


class TenantRole(models.Model):
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="roles")
    name = models.CharField(max_length=100)

    class TenantRoleChoices(models.IntegerChoices):
        TENANT_ADMIN = 1, "Super Admin"

    role_type = models.IntegerField(
        choices=TenantRoleChoices.choices, default=TenantRoleChoices.TENANT_ADMIN
    )

    def __str__(self):
        return f"{self.name} ({self.tenant.name or 'Unnamed Tenant'})"


class TenantRolePermissions(models.Model):
    role = models.ForeignKey(TenantRole, on_delete=models.CASCADE)
    permission = models.IntegerField(choices=TenantPermissionChoices.choices)
    permission_text = models.CharField(max_length=100, editable=False)

    def __str__(self):
        return f"{self.role.name} - {self.permission_text}"

    def save(self, *args, **kwargs):
        self.permission_text = TenantPermissionChoices(self.permission).label
        super().save(*args, **kwargs)
