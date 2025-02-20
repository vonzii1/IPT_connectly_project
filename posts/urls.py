from django.urls import path
from . import views
from .views import UserListCreate, PostListCreate, CommentListCreate, LikeListCreate
from rest_framework.authtoken.views import obtain_auth_token

urlpatterns = [
  
    # For Index
    path('', views.index, name='index'),
    # For GET users
    path('users/', UserListCreate.as_view(), name='user-list'), 
    # For POST user
    path('users/create/', UserListCreate.as_view(), name='user-create'),  
    # For PUT and DELETE users
    path('users/<int:pk>/', UserListCreate.as_view(), name='user-detail'),  
    # For GET posts
    path('posts/<int:pk>/', PostListCreate.as_view(), name='post-list'),
    # For POST posts
    path('posts/create/', PostListCreate.as_view(), name='post-create'),
    # For PUT and DELETE posts
    path('posts/<int:pk>/', PostListCreate.as_view(), name='post-detail'),  
    # For GET comments
    path('<int:pk>/comments/', CommentListCreate.as_view(), name='comment-list'),
    # For POST comments
    path('<int:pk>/comments/', CommentListCreate.as_view(), name='comment-create'),
    # For PUT and DELETE comments
    path('comments/<int:pk>/', CommentListCreate.as_view(), name='comment-detail'),  
    # For GET likes
    path('likes/', LikeListCreate.as_view(), name='like-list'),
    # For POST likes
    path('<int:pk>/likes/', LikeListCreate.as_view(), name='like-create'),
    # For PUT and DELETE likes
    path('likes/<int:pk>/', LikeListCreate.as_view(), name='like-detail'),
    
    path('get_posts/', views.get_posts, name='get_posts'),
    # For login
    path('login/', views.login_view, name='login'),
    # For logout
    path('logout/', views.logout_view, name='logout'),
    # For homepage
    path('home/', views.home, name='home'),
    # For signup
    path('sign-up/', views.sign_up, name='sign_up'),
    
    # Token URL
    path('api-token-auth/', obtain_auth_token, name='api-token-auth'),
    

]