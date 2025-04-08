from django.db import models
from authentication.models import User
from django.contrib.auth.hashers import make_password, check_password
# Create your models here.


class Tenant(models.Model):
    tenant_id = models.ForeignKey(User, on_delete=models.CASCADE)
    username = models.CharField(max_length=150,unique=True)
    hashed_password = models.CharField(max_length=255)
    full_name = models.CharField(max_length=150)
    created_at = models.DateTimeField(auto_now_add=True)


    def set_password(self, raw_password):
        self.hashed_password = make_password(raw_password)

    def check_password(self, raw_password):
        return check_password(raw_password, self.hashed_password)

    def __str__(self):
        return f"{self.username} ({self.tenant_id})"

