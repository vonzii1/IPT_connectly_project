from django.contrib import admin
from django.urls import path, include
from posts import views
from posts.views import get_config_setting, update_config_setting

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index, name='index'),
    path('posts/', include('posts.urls')),
    path('api/config/', get_config_setting, name='get_config_setting'), 
    path('posts/', include('posts.urls')),
    path('__debug__/', include('debug_toolbar.urls')),
    path('api/config/update/', update_config_setting, name='update_config_setting'),
    path('api/', include('posts.urls')),
]