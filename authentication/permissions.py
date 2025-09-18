from rest_framework.permissions import BasePermission


class IsTenant(BasePermission):
    """
    Custom permission to only allow access to users with is_merchant flag set to True.
    """

    def has_permission(self, request, view):
        return bool(request.user.is_authenticated and request.user.is_tenant)


class IsAdminUser(BasePermission):
    """
    Allows access only to admin users.
    """

    def has_permission(self, request, view):
        return bool(request.user.is_authenticated) and (
            request.user.is_admin or request.user.is_super_admin
        )


class IsSuperAdminUser(BasePermission):
    """
    Allows access only to admin users.
    """

    def has_permission(self, request, view):
        return bool(request.user.is_authenticated) and (request.user.is_super_admin)


class IsReadonlyAdminUser(BasePermission):
    """
    Allows access only to admin users.
    """

    def has_permission(self, request, view):
        return bool(request.user.is_authenticated) and (
            request.user.is_admin
            or request.user.is_super_admin
            or request.user.is_read_only
        )
