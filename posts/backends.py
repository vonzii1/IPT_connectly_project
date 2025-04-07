from django.conf import settings
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import logging
from django.contrib.auth.models import Group

logger = logging.getLogger(__name__)

User = get_user_model()


class GoogleOAuth2Backend(BaseBackend):
    def authenticate(self, request, id_token_str=None, **kwargs):
        logger.info("Custom backend is being called!")
        try:
            # Verify the ID token using Google's API
            id_info = id_token.verify_oauth2_token(id_token_str, google_requests.Request(), settings.GOOGLE_OAUTH_CLIENT_ID)

            # Log the ID token info for debugging
            logger.info(f"ID token info: {id_info}")

            # Extract user information from the ID token
            email = id_info.get('email')
            if not email:
                logger.error("No email found in ID token")
                return None

            # Log the email for debugging
            logger.info(f"Authenticating user with email: {email}")

            # Get or create the user
            user, created = User.objects.get_or_create(email=email)

            # Update user details from Google profile
            if created:
                user.username = email  # Use email as username
                user.first_name = id_info.get('given_name', '')
                user.last_name = id_info.get('family_name', '')
                user.save()
                logger.info(f"New user created: {user}")
                
                # Add the user to the "User" group
                user_group, created = Group.objects.get_or_create(name='User')
                user.groups.add(user_group)
            else:
                logger.info(f"Existing user logged in: {user}")

            return user
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None