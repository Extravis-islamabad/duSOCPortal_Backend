from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.db import models

from common.utils import PasswordCreation  # your custom password hashing class


class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email and not username:
            raise ValueError("At least one of email or username must be provided")

        if email:
            email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        if password:
            user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault("is_tenant", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_admin", True)

        if extra_fields.get("is_tenant") is not True:
            raise ValueError("Superuser must have is_tenant=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, username, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    name = models.CharField(max_length=100, blank=True, null=True)
    email = models.EmailField(unique=True, null=True, blank=True)
    username = models.CharField(max_length=100, unique=True)
    hashed_password = models.CharField(max_length=255, blank=True, null=True)
    is_super_admin = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_tenant = models.BooleanField(default=False)  # Needed for admin access
    profile_picture = models.ImageField(
        upload_to="profile_pictures/", blank=True, null=True
    )
    company_name = models.CharField(max_length=100, blank=True, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = CustomUserManager()

    USERNAME_FIELD = "username"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.username

    def set_password(self, raw_password):
        if raw_password:
            self.hashed_password = PasswordCreation._make_password(raw_password)
        else:
            self.hashed_password = None

    def check_password(self, raw_password):
        return PasswordCreation._check_password(raw_password, self.hashed_password)


class UserPermissionChoices(models.IntegerChoices):
    DASHBOARD = 1, "Dashboard"
    CHATBOT = 2, "Chatbot"
    REPORTS = 3, "Reports"
    THREAT_INTELLIGENCE = 4, "Threat Intelligence"
    ASSETS = 5, "Assets"


class Role(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="roles")
    name = models.CharField(max_length=100)

    class RoleChoices(models.IntegerChoices):
        SUPER_ADMIN = 1, "Super Admin"
        ADMIN = 2, "Admin"
        USER = 3, "User"

    role_type = models.IntegerField(
        choices=RoleChoices.choices, default=RoleChoices.USER
    )

    def __str__(self):
        return f"{self.name} ({self.get_role_type_display()})"


class UserRole(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.user.username} - {self.role.name}"


class RolePermission(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    permission = models.IntegerField(
        choices=UserPermissionChoices.choices, default=UserPermissionChoices.DASHBOARD
    )
    permission_text = models.CharField(
        max_length=100,
        editable=False,  # Prevent manual edits
        help_text="Automatically set to the text label of the permission choice",
        default=UserPermissionChoices.DASHBOARD.label,
    )

    def __str__(self):
        return f"{self.role.name} - {self.permission_text}"

    def save(self, *args, **kwargs):
        # Set permission_text to the label from PermissionChoices based on permission
        self.permission_text = UserPermissionChoices(self.permission).label
        super().save(*args, **kwargs)
