from django.db.models.signals import post_save
from django.contrib.auth.models import Permission, User
from django.dispatch import receiver

@receiver(post_save, sender=User)
def assign_permissions(sender, instance, created, **kwargs):
    if created:
        permissions = [
            'add_post', 'change_post', 'delete_post',
            'add_comment', 'delete_comment',
            'add_like', 'delete_like'
        ]
        for perm in permissions:
            instance.user_permissions.add(
                Permission.objects.get(codename=perm))