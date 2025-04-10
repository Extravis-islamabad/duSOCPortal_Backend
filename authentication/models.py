from django.db import models

from common.utils import PasswordCreation


class User(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=100, unique=True)
    hashed_password = models.CharField(max_length=255)
    is_super_admin = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def set_password(self, raw_password):
        self.hashed_password = PasswordCreation.make_password(raw_password)

    def check_password(self, raw_password):
        return PasswordCreation.check_password(raw_password, self.hashed_password)


class Permission(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name


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


# RolePermission Model
class RolePermission(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.role.name} - {self.permission.name}"
