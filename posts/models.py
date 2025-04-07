from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User

# Post model
class Post(models.Model):
    POST_TYPES = (
        ('text', 'Text'),
        ('image', 'Image'),
        ('video', 'Video'),
    )
    post_type = models.CharField(max_length=10, choices=POST_TYPES)
    title = models.CharField(max_length=255)
    content = models.TextField()
    metadata = models.JSONField(default=dict)
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    private = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.content[:50]
    
class Comment(models.Model):
    text = models.TextField()
    author = models.ForeignKey(User, related_name='comments', on_delete=models.CASCADE)
    post = models.ForeignKey(Post, related_name='comments', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Comment by {self.author.username} on Post {self.post.id}"

class Like(models.Model):
    author = models.ForeignKey(User, related_name='likes', on_delete=models.CASCADE)
    post = models.ForeignKey(Post, related_name='likes', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Like by {self.author.username} on Post {self.post.id}"