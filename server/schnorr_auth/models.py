from django.db import models
import uuid


class User(models.Model):
    """Store user credentials"""
    client_id = models.CharField(max_length=255, unique=True)
    secret_y = models.CharField(max_length=255)  # g^x mod p
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"User {self.client_id}"


class Commitment(models.Model):
    """Store commitment during authentication"""
    client_id = models.CharField(max_length=255, unique=True)
    t = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Commitment for {self.client_id}"


class AuthToken(models.Model):
    """Store authentication tokens"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='auth_token')
    token = models.CharField(max_length=255, unique=True, default=uuid.uuid4)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Token for {self.user.client_id}"
