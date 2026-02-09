from django.db import models


class Commitment(models.Model):
    client_id = models.CharField(max_length=255, unique=True)
    t = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Commitment for {self.client_id}"
