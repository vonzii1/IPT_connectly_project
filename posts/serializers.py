from rest_framework import serializers
from .models import Post, Comment, Like
from django.contrib.auth.models import User


class UserSerializer(serializers.ModelSerializer):
   class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name', 'email']


class PostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Post
        fields = '__all__'
        extra_kwargs = {
            'private': {'required': False}  
        }

    private = serializers.BooleanField(default=False)

class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comment
        fields = ['id', 'text', 'author', 'post', 'created_at']


    def validate_post(self, value):
        if not Post.objects.filter(id=value.id).exists():
            raise serializers.ValidationError("Post not found.")
        return value


    def validate_author(self, value):
        if not User.objects.filter(id=value.id).exists():
            raise serializers.ValidationError("Author not found.")
        return value


class LikeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Like
        fields = ['id', 'author', 'post', 'created_at']


    def validate_post(self, value):
        if not Post.objects.filter(id=value.id).exists():
            raise serializers.ValidationError("Post not found.")
        return value


    def validate_author(self, value):
        if not User.objects.filter(id=value.id).exists():
            raise serializers.ValidationError("Author not found.")
        return value