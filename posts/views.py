import json
from venv import logger
from django.shortcuts import render
from django.http import HttpResponseRedirect, JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .models import Post, Comment, Like
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from .serializers import UserSerializer, PostSerializer, CommentSerializer, LikeSerializer
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
from rest_framework.authtoken.models import Token
from django.db import IntegrityError, models
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from .permissions import IsPostAuthor
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.backends import BaseBackend
from .factory.post_factory import PostFactory
from .factory.comment_factory import CommentFactory
from .factory.like_factory import LikeFactory
from .logger_singleton import LoggerSingleton
from .config_manager import ConfigManager
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from posts.backends import GoogleOAuth2Backend 
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.views import SocialLoginView
from django.conf import settings
from urllib.parse import urljoin
import requests
from django.urls import reverse
import jwt  # Import the jwt module
from rest_framework import status
from rest_framework.response import Response
import logging
from .utils import get_tokens_for_user  # Import the function
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from rest_framework.authentication import SessionAuthentication, TokenAuthentication



class MySocialAccountAdapter(DefaultSocialAccountAdapter):
    def pre_social_login(self, request, sociallogin):
        print(sociallogin.account.extra_data) 
# get_config_setting
def get_config_setting(request):
        config = ConfigManager()
        setting_key = request.GET.get('key')  
        if setting_key:
            setting_value = config.get_setting(setting_key)
            return JsonResponse({setting_key: setting_value})
        else:
            return JsonResponse({'error': 'Key not provided'}, status=400)

# update_config_setting
def update_config_setting(request):
    config = ConfigManager()
    key = request.GET.get('key')
    value = request.GET.get('value')
    if key and value:
        config.set_setting(key, value)
        return JsonResponse({"message": f"Setting {key} updated to {value}"})
    else:
        return JsonResponse({"error": "Key and value are required"}, status=400)

logger = logging.getLogger(__name__)



class GoogleLoginCallback(APIView):
    def get(self, request, *args, **kwargs):
        # Log the incoming request
        logger.info("Google OAuth2 callback received.")
        logger.debug(f"Request GET parameters: {request.GET}")

        # Extract the authorization code from the request
        code = request.GET.get("code")
        if not code:
            logger.error("Authorization code not found in the request.")
            return Response({"error": "Authorization code not found"}, status=status.HTTP_400_BAD_REQUEST)

        logger.info(f"Authorization code received: {code}")

        # Exchange the code for tokens
        token_endpoint = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
            "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET,
            "redirect_uri": settings.GOOGLE_OAUTH_CALLBACK_URL,
            "grant_type": "authorization_code",
        }

        logger.debug(f"Sending token exchange request to Google: {token_endpoint}")
        logger.debug(f"Token exchange data: {data}")

        try:
            # Send the token exchange request to Google
            response = requests.post(token_endpoint, data=data)
            response.raise_for_status()  # Raise HTTP errors
            logger.info("Token exchange with Google successful.")
            logger.debug(f"Token exchange response: {response.json()}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Token exchange failed: {str(e)}")
            return Response({"error": "Failed to exchange code for tokens"}, status=status.HTTP_400_BAD_REQUEST)

        # Parse the token response
        token_data = response.json()
        id_token_str = token_data.get("id_token")
        if not id_token_str:
            logger.error("ID token missing in Google response.")
            return Response({"error": "ID token missing"}, status=status.HTTP_400_BAD_REQUEST)

        logger.info("ID token received from Google.")

        # Authenticate the user using the ID token
        user = authenticate(request, id_token_str=id_token_str, backend=GoogleOAuth2Backend)
        if not user:
            logger.error("User authentication failed.")
            return Response({"error": "Authentication failed"}, status=status.HTTP_401_UNAUTHORIZED)

        logger.info(f"User authenticated: {user}")

        # Log in the user and set session/cookie
        login(request, user)
        token, _ = Token.objects.get_or_create(user=user)
        logger.info(f"Token created for user: {token.key}")

        # Redirect the user after successful login
        response = HttpResponseRedirect('/posts/home/')

        response.set_cookie(
            key='token',
            value=token.key,
            httponly=True,  # For security
            secure=not settings.DEBUG,  # Use HTTPS in production
        )
        logger.info("User logged in and redirected.")
        return response

class GoogleOAuth2Backend(BaseBackend):
    def authenticate(self, request, id_token_str=None):
        if not id_token_str:
            logger.error("ID token is missing.")
            return None

        try:
            decoded_token = jwt.decode(id_token_str, options={"verify_signature": False})
            logger.info(f"Decoded ID Token: {json.dumps(decoded_token, indent=2)}")  # Log the full token
        except jwt.ExpiredSignatureError:
            logger.error("ID Token has expired.")
            return None

        email = decoded_token.get("email")
        if not email:
            logger.error("Email missing in ID token.")
            return None

        User = get_user_model()
        user, created = User.objects.get_or_create(email=email, defaults={'username': email})
        
        if created:
            logger.info(f"New user created: {email}")
        else:
            logger.info(f"Existing user logged in: {email}")
        
        return user    

class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter
    callback_url = "http://127.0.0.1:8000/accounts/google/login/callback/"
    client_class = OAuth2Client


# Index View
def index(request, *args, **kwargs):
   
    if request.user.is_authenticated:
        return redirect('/posts/home/')
    
    return render(
        request, 
        'index.html',
        {
            "google_callback_uri": settings.GOOGLE_OAUTH_CALLBACK_URL,
            "google_client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
        },
    )


# Home View
def home(request):
    # If the user is not authenticated, redirect to the login page
    if not request.user.is_authenticated:
        return redirect('/accounts/login/')  # Make sure this line exists

    user = request.user
    posts = Post.objects.all()
    comments = Comment.objects.all()

    return render(request, 'home.html', {
        'token': request.COOKIES.get('token'),
        'user': user,
        'posts': posts,
        'comments': comments
    })




# Sign Up View
def sign_up(request):
    return render(request, 'sign-up.html')

# Improved error handling for user authentication
def login_view(request):
    if request.method == 'POST':
        # Handle login logic
        ...
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)


# Index View
def home(request):
    if not request.user.is_authenticated:
        return redirect('/accounts/login/')
    
    if request.scheme == 'https':
        return redirect('http://127.0.0.1:8000/posts/home/') 

    # Get the logged-in user and all posts with comments
    user = request.user
    posts = Post.objects.all()
    comments = Comment.objects.all()

    return render(request, 'home.html', {
        'token': request.COOKIES.get('token'),
        'user': user,
        'posts': posts,
        'comments': comments
    })

# Get users
def get_users(request):
    try:
        users = list(User.objects.values('id', 'username', 'email', 'created_at'))
        return JsonResponse(users, safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

# Get posts
def get_posts(request):
    try:
        posts = Post.objects.all()
        posts_with_comments = []
        for post in posts:
            comments = Comment.objects.filter(post=post)
            comments_with_authors = []
            for comment in comments:
                author = User.objects.get(id=comment.author.id)
                comment_data = {
                    'id': comment.id,
                    'text': comment.text,
                    'author': {
                        'id': author.id,
                        'username': author.username,
                        'email': author.email,
                        'created_at': author.created_at
                    },
                    'created_at': comment.created_at
                }
                comments_with_authors.append(comment_data)
            post_data = {
                'id': post.id,
                'content': post.content,
                'author': {
                    'id': post.author.id,
                    'username': post.author.username,
                    'email': post.author.email,
                    'created_at': post.author.created_at
                },
                'created_at': post.created_at,
                'comments': comments_with_authors
            }
            posts_with_comments.append(post_data)
        return JsonResponse(posts_with_comments, safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

# Old Login
@csrf_exempt
def login_view(request):
    logger = LoggerSingleton().get_logger()
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            password = data.get('password')

            if not username or not password:
                logger.warning("Username and password are required for login.")
                return JsonResponse({'error': 'Username and password are required'}, status=400)

            user = authenticate(request, username=username, password=password)
            if user:
                # Create or retrieve token
                token, created = Token.objects.get_or_create(user=user)
                
                # Log in the user (for session-based authentication)
                login(request, user)

                logger.info(f"User {username} logged in successfully.")
                # Return both token and session info
                return JsonResponse({
                    'message': 'Login successful',
                    'token': token.key,
                    'user': user.username,
                    'id': user.id,
                    'email': user.email
                }, status=200)
            else:
                logger.warning(f"Invalid login attempt for username: {username}")
                return JsonResponse({'error': 'Invalid username or password'}, status=400)

        except json.JSONDecodeError:
            logger.error("Invalid JSON format in login request.")
            return JsonResponse({'error': 'Invalid JSON format'}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

# Logout
@csrf_exempt
def logout_view(request):
    logger = LoggerSingleton().get_logger()
    if request.method == 'POST':
        # Handle token-based logout first
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        
        if not auth_header or not auth_header.startswith('Token '):
            logger.warning("Authorization header with token is required for logout.")
            return JsonResponse({'error': 'Authorization header with token is required'}, status=400)
        
        token_key = auth_header.split('Token ')[1]
        
        try:
            #token = Token.objects.get(key=token_key)
            #token.delete()  # Delete the token to log out the user
            
            # Token was deleted successfully, now clear the session
            if request.user.is_authenticated:
                logout(request)  # This clears the session
                logger.info(f"User {request.user.username} logged out successfully.")
            
            return JsonResponse({'message': 'Logout successful, token and session cleared'}, status=200)
        
        except Token.DoesNotExist:
            # Token is invalid, don't log out the session
            logger.warning("Invalid token provided for logout.")
            return JsonResponse({'error': 'Invalid token'}, status=401)
    
    # If no valid token and no valid request method
    return JsonResponse({'error': 'Invalid request method'}, status=405)

# User API
class UserListCreate(APIView):
    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(
            {
                'status': 'success',
                'users': serializer.data,
                'code': status.HTTP_200_OK,
            }
        )

    def post(self, request):
        data = request.data
        if 'password' not in data:
            return Response(
                {
                    'status': 'failure',
                    'errors': 'Password is required',
                    'code': status.HTTP_400_BAD_REQUEST
                }
            )
        if 'first_name' not in data:
            return Response(
                {
                    'status': 'failure',
                    'errors': 'First name is required',
                    'code': status.HTTP_400_BAD_REQUEST
                }
            )
        if 'last_name' not in data:
            return Response(
                {
                    'status': 'failure',
                    'errors': 'Last name is required',
                    'code': status.HTTP_400_BAD_REQUEST
                }
            )
        data['password'] = make_password(data['password'])
        
        user = User.objects.create_user(**data)
        return Response(
            {
                'status': 'success',
                'user': UserSerializer(user).data,
                'code': status.HTTP_201_CREATED
            }
        )

    def put(self, request, pk):
        try:
            user = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response(
                {
                    'status': 'failure',
                    'error': 'User not found',
                    'code': status.HTTP_404_NOT_FOUND
                }
            )

        data = request.data
        if 'password' in data:
            data['password'] = make_password(data['password'])  # Hash the new password if provided
        serializer = UserSerializer(user, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    'status': 'success',
                    'user': serializer.data,
                    'code': status.HTTP_200_OK
                }
            )
        return Response(
            {
                'status': 'failure',
                'errors': serializer.errors,
                'code': status.HTTP_400_BAD_REQUEST
            }
        )

    def delete(self, request, pk):
        try:
            user = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response(
                {
                    'error': 'User not found',
                    'code': status.HTTP_404_NOT_FOUND
                 })

        user.delete()
        return Response(
            {
                'status': 'success',
                'message': 'User deleted successfully',
                'code': status.HTTP_204_NO_CONTENT
            })

# Post API
class PostListCreate(APIView):
    permission_classes = [permissions.IsAuthenticated]
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    private = models.BooleanField(default=False)
    
    def perform_create(self, serializer):
        private = serializer.validated_data.get('private', False)
        serializer.save(
            user=self.request.user,
            private=serializer.validated_data.get('private', False)
        )

    def get(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)
            comments_count = Comment.objects.filter(post=post).count()
            likes_count = Like.objects.filter(post=post).count()

            post_data = {
                'id': post.id,
                'content': post.content,
                'author': {
                    'id': post.author.id,
                    'username': post.author.username,
                    'email': post.author.email                   
                },
                'created_at': post.created_at,
                'comments_count': comments_count,
                'likes_count': likes_count
            }

            return Response(
                {
                    'status': 'success',
                    'post': post_data,
                    'code': status.HTTP_200_OK
                })
        except Post.DoesNotExist:
            return Response(
                {
                    'status': 'failure',
                    'error': 'Post not found',
                    'code': status.HTTP_404_NOT_FOUND
                }
            )

    def post(self, request):
        logger = LoggerSingleton().get_logger()
        data = request.data
        if 'post_type' not in data or 'title' not in data or 'content' not in data:
            logger.error("Post type, title, and content are required.")
            return Response(
                {
                    'status': 'failure',
                    'errors': 'Post type, title, and content are required',
                    'code': status.HTTP_400_BAD_REQUEST
                }
            )
        
        # Set default metadata if post_type is "text" and metadata is not provided
        if data['post_type'] == 'text' and 'metadata' not in data:
            config_manager = ConfigManager()
            data['metadata'] = config_manager.get_setting("DEFAULT_TEXT_METADATA")
        
        try:
            post = PostFactory.create_post(
                author=request.user,
                post_type=data['post_type'],
                title=data['title'],
                content=data.get('content', ''),
                metadata=data.get('metadata', {}),
                private=data.get('private', False)
            )
            post.save()
            serializer = PostSerializer(post)
            logger.info(f"Post created successfully by user {request.user}.")
            return Response({'message': 'Post created successfully!', 'post_id': post.id, 'data': serializer.data}, status=status.HTTP_201_CREATED)
        except ValueError as e:
            logger.error(f"Error creating post: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        logger = LoggerSingleton().get_logger()
        try:
            post = Post.objects.get(pk=pk)
        except Post.DoesNotExist:
            logger.error(f"Post with id {pk} not found.")
            return Response(
                {
                    'status': 'failure',
                    'error': 'Post not found',
                    'code': status.HTTP_404_NOT_FOUND
                }
            )
        
        # Check if the authenticated user is the author
        if post.author != request.user:
            logger.warning(f"User {request.user} is not authorized to edit post {pk}.")
            return Response(
                {
                    'status': 'failure',
                    'error': 'You are not authorized to edit this post',
                    'code': status.HTTP_403_FORBIDDEN
                }
            )

        data = request.data
        post = PostFactory.create_post(
            author=request.user,
            post_type=data['post_type'],
            title=data['title'],
            content=data.get('content', ''),
            metadata=data.get('metadata', {}),
            private=data.get('private', False)

        )
        post.id = pk  # Ensure the post ID remains the same
        post.save()
        serializer = PostSerializer(post)
        logger.info(f"Post {pk} updated successfully by user {request.user}.")
        return Response(
            {
                'status': 'success',
                'post': serializer.data,
                'code': status.HTTP_200_OK
            }
        )

    def delete(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)
        except Post.DoesNotExist:
            return Response(
                {
                    'status': 'failure',
                    'error': 'Post not found',
                    'code': status.HTTP_404_NOT_FOUND
                }
            )
        
        # Check if the authenticated user is the author
        if post.author != request.user:
            return Response(
                {
                    'status': 'failure',
                    'error': 'You are not authorized to delete this post',
                    'code': status.HTTP_403_FORBIDDEN
                }
            )

        post.delete()
        return Response(
            {
                'status': 'success',
                'message': 'Post deleted successfully',
                'code': status.HTTP_204_NO_CONTENT
            }
        )

# Comment API
class CommentListCreate(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)
            comments = Comment.objects.filter(post=post)
            serializer = CommentSerializer(comments, many=True)
            return Response(
                {
                    'status': 'success',
                    'comments': serializer.data,
                    'code': status.HTTP_200_OK
                })
        except Post.DoesNotExist:
            return Response(
                {
                    'status': 'failure',
                    'error': 'Post not found',
                    'code': status.HTTP_404_NOT_FOUND
                }
            )

    def post(self, request, pk):
        data = request.data
        if 'text' not in data:
            return Response(
                {
                    'status': 'failure',
                    'errors': 'Text is required',
                    'code': status.HTTP_400_BAD_REQUEST
                }
            )
        try:
            post = Post.objects.get(pk=pk)
            comment = CommentFactory.create_comment(
                author=request.user,
                post=post,
                text=data['text']
            )
            comment.save()
            serializer = CommentSerializer(comment)
            return Response(
                {
                    'status': 'success',
                    'comment': serializer.data,
                    'code': status.HTTP_201_CREATED
                })
        except Post.DoesNotExist:
            return Response(
                {
                    'status': 'failure',
                    'error': 'Post not found',
                    'code': status.HTTP_404_NOT_FOUND
                }
            )
        except ValueError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        logger = LoggerSingleton().get_logger()
        try:
            comment = Comment.objects.get(pk=pk)
        except Comment.DoesNotExist:
            logger.error(f"Comment with id {pk} not found.")
            return Response(
                {
                    'status': 'failure',
                    'error': 'Comment not found',
                    'code': status.HTTP_404_NOT_FOUND
                }
            )
        
        # Check if the authenticated user is the author of the comment
        if comment.author != request.user:
            logger.warning(f"User {request.user} is not authorized to edit comment {pk}.")
            return Response(
                {
                    'status': 'failure',
                    'error': 'You are not authorized to edit this comment',
                    'code': status.HTTP_403_FORBIDDEN
                }
            )

        data = request.data
        if 'text' not in data:
            logger.error("Text is required to update the comment.")
            return Response(
                {
                    'status': 'failure',
                    'errors': 'Text is required',
                    'code': status.HTTP_400_BAD_REQUEST
                }
            )

        try:
            comment = CommentFactory.update_comment(comment, text=data['text'])
            serializer = CommentSerializer(comment)
            logger.info(f"Comment {pk} updated successfully by user {request.user}.")
            return Response(
                {
                    'status': 'success',
                    'comment': serializer.data,
                    'code': status.HTTP_200_OK
                }
            )
        except ValueError as e:
            logger.error(f"Error updating comment {pk}: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        try:
            comment = Comment.objects.get(pk=pk)
        except Comment.DoesNotExist:
            return Response(
                {
                    'status': 'failure',
                    'error': 'Comment not found',
                    'code': status.HTTP_404_NOT_FOUND
                }
            )
        
        # Check if the authenticated user is the author of the comment
        if comment.author != request.user:
            return Response(
                {
                    'status': 'failure',
                    'error': 'You are not authorized to delete this comment',
                    'code': status.HTTP_403_FORBIDDEN
                }
            )

        comment.delete()
        return Response(
            {
                'status': 'success',
                'message': 'Comment deleted successfully',
                'code': status.HTTP_204_NO_CONTENT
            }
        )
# Like API
class LikeListCreate(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        likes = Like.objects.all()
        serializer = LikeSerializer(likes, many=True)
        return Response(
            {
                'status': 'success',
                'likes': serializer.data,
                'code': status.HTTP_200_OK
            })
    
    def post(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)
            like = LikeFactory.create_like(
                author=request.user,
                post=post
            )
            like.save()
            serializer = LikeSerializer(like)
            return Response(
                {
                    'status': 'success',
                    'like': serializer.data,
                    'code': status.HTTP_201_CREATED
                })
        except Post.DoesNotExist:
            return Response(
                {
                    'status': 'failure',
                    'error': 'Post not found',
                    'code': status.HTTP_404_NOT_FOUND
                }
            )
        except ValueError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, post_pk):
        try:
            like = Like.objects.get(pk=post_pk)
        except Like.DoesNotExist:
            return Response(
                {
                    'status': 'failure',
                    'error': 'Like not found',
                    'code': status.HTTP_404_NOT_FOUND
                }
            )
        
        # Check if the authenticated user is the author of the like
        if like.author != request.user:
            return Response(
                {
                    'status': 'failure',
                    'error': 'You are not authorized to delete this like',
                    'code': status.HTTP_403_FORBIDDEN
                }
            )

        like.delete()
        return Response(
            {
                'status': 'success',
                'message': 'Like deleted successfully',
                'code': status.HTTP_204_NO_CONTENT
            }
        )
        
# News Feed API
class NewsFeed(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Get query parameters for pagination and filtering
            page = int(request.GET.get('page', 1))
            page_size = int(request.GET.get('page_size', 5))
            liked_by_user = request.GET.get('liked_by_user', 'false').lower() == 'true'

            # Get all posts or filter by posts liked by the user
            if liked_by_user:
                posts = Post.objects.filter(like__author=request.user).distinct()
            else:
                posts = Post.objects.all()

            # Sort posts by creation date
            posts = posts.order_by('-created_at')

            # Paginate the results
            start = (page - 1) * page_size
            end = start + page_size
            paginated_posts = posts[start:end]

            posts_data = []
            for post in paginated_posts:
                comments_count = Comment.objects.filter(post=post).count()
                likes_count = Like.objects.filter(post=post).count()

                # Get author details
                author = {
                    'id': post.author.id,
                    'username': post.author.username,
                    'email': post.author.email,
                    'first_name': post.author.first_name,
                    'last_name': post.author.last_name
                }

                # Get comments with author details
                comments = Comment.objects.filter(post=post)
                comments_data = []
                for comment in comments:
                    comment_author = {
                        'id': comment.author.id,
                        'username': comment.author.username,
                        'email': comment.author.email,
                        'first_name': comment.author.first_name,
                        'last_name': comment.author.last_name
                    }
                    comments_data.append({
                        'id': comment.id,
                        'text': comment.text,
                        'author': comment_author,
                        'created_at': comment.created_at
                    })

                post_data = {
                    'id': post.id,
                    'content': post.content,
                    'author': author,
                    'created_at': post.created_at,
                    'comments_count': comments_count,
                    'likes_count': likes_count,
                    'comments': comments_data
                }
                posts_data.append(post_data)

            return Response(
                {
                    'status': 'success',
                    'posts': posts_data,
                    'page': page,
                    'page_size': page_size,
                    'total_posts': posts.count(),
                    'code': status.HTTP_200_OK
                })
        except Exception as e:
            return Response(
                {
                    'status': 'failure',
                    'error': str(e),
                    'code': status.HTTP_500_INTERNAL_SERVER_ERROR
                }
            )
