from rest_framework.permissions import BasePermission

class IsPostAuthor(BasePermission):
    """Only the author of the post can edit or delete it."""
    def has_object_permission(self, request, view, obj):
        return obj.author == request.user

class IsAdminUser(BasePermission):
    """Only users in the Admin group can access."""
    def has_permission(self, request, view):
        return request.user.groups.filter(name="Admin").exists()

class IsUser(BasePermission):
    """Only users in the User group can access."""
    def has_permission(self, request, view):
        return request.user.groups.filter(name="User").exists()

class IsGuest(BasePermission):
    """Allow access to unauthenticated users."""
    def has_permission(self, request, view):
        return not request.user.is_authenticated