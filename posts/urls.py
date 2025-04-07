from django.urls import path, include
from . import views
from .views import (
    UserListCreate, 
    PostListCreate, 
    CommentListCreate, 
    LikeListCreate, 
    NewsFeed,
    get_posts
)
from rest_framework.authtoken.views import obtain_auth_token

urlpatterns = [
    # Frontend/authentication routes
    path('', views.index, name='index'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('home/', views.home, name='home'),
    path('sign-up/', views.sign_up, name='sign_up'),
    path('accounts/', include('allauth.urls')),
    
    # API Authentication
    path('api-token-auth/', obtain_auth_token, name='api-token-auth'),
    
    # API Endpoints
    # User endpoints
    path('users/', UserListCreate.as_view(), name='user-list'),  # GET all users
    path('users/create/', UserListCreate.as_view(), name='user-create'),  # POST new user
    path('users/<int:pk>/', UserListCreate.as_view(), name='user-detail'),  # PUT/DELETE user
    
    # Post endpoints
    path('posts/', PostListCreate.as_view(), name='post-list'),  # GET all posts
    path('posts/create/', PostListCreate.as_view(), name='post-create'),  # POST new post
    path('posts/<int:pk>/', PostListCreate.as_view(), name='post-detail'),  # GET/PUT/DELETE single post
    
    # Comment endpoints
    path('posts/<int:post_pk>/comments/', CommentListCreate.as_view(), name='comment-list'),  # GET/POST comments for post
    path('comments/<int:pk>/', CommentListCreate.as_view(), name='comment-detail'),  # PUT/DELETE comment
    
    # Like endpoints
    path('likes/', LikeListCreate.as_view(), name='like-list'),  # GET all likes
    path('posts/<int:pk>/likes/', LikeListCreate.as_view(), name='like-post'),  # POST new like
    path('likes/<int:pk>/', LikeListCreate.as_view(), name='like-detail'),  # DELETE like
    
    # News Feed
    path('feed/', NewsFeed.as_view(), name='news_feed'),
    
    # Legacy endpoint (consider removing if redundant with posts/)
    path('get_posts/', get_posts, name='get_posts'),
]