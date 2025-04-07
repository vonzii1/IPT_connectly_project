from django.contrib import admin
from django.urls import path, include
from posts.views import GoogleLogin, GoogleLoginCallback
from posts import views  
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index, name='index'),
    
    path('posts/', include('posts.urls')),
    path('api/v1/posts/', include('posts.urls')),
    path("api/v1/auth/", include("dj_rest_auth.urls")),
    path("api/v1/auth/accounts/", include("allauth.urls")),
    path("api/v1/auth/registration/", include("dj_rest_auth.registration.urls")),
    path("api/v1/auth/google/", GoogleLogin.as_view(), name="google_login"),
    path('api/v1/auth/google/callback/',GoogleLoginCallback.as_view(),name="google_login_callback",),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('accounts/', include('allauth.urls')),
    
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)