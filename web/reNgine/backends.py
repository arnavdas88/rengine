from typing import Optional
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django import forms
from django.db.models import Q

from django.core.validators import validate_email
from django.core.exceptions import ValidationError

def validateEmail( email ):
    try:
        validate_email( email )
        return True
    except ValidationError:
        return False


class EmailBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        is_email = False
        try:
            if validateEmail(username):
                # Mail Address Validation
                f = forms.EmailField()
                username = f.clean(username).lower() # Sanitizing Mail Address
                is_email = True
                user = UserModel.objects.get(Q(email=username))
            else:
                # Username Validation
                user = UserModel.objects.get(Q(username=username))
        except UserModel.DoesNotExist:
            # User Exists Validation
            return None
        except UserModel.MultipleObjectsReturned:
            # Multiple User Exists Validation
            if is_email:
                users = UserModel.objects.filter(Q(email=username))
            else:
                users = UserModel.objects.filter(Q(username=username))
            for user in users:
                # Select Proper User By Verifying Password
                if user.check_password(password):
                    return user
            return None
        else:
            # Single User Exists
            if user.check_password(password):
                return user
        return None

    def user_can_authenticate(self, user) -> bool:
        """
        Reject users with is_active=False. Custom user models that don't have
        that attribute are allowed.
        """
        is_active = getattr(user, 'is_active', None)
        return is_active or is_active is None


    def get_user(self, user_id):
        UserModel = get_user_model()
        try:
            user = UserModel._default_manager.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
        return user if self.user_can_authenticate(user) else None
