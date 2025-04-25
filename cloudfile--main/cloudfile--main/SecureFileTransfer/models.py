from django.db import models

class StoreUserDatas(models.Model):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)  # You can use hashed passwords if you want later

    def __str__(self):
        return self.username
class EncryptedUpload(models.Model):
    email = models.EmailField()
    filename = models.CharField(max_length=255)
    password = models.CharField(max_length=255)  # Optional: consider encrypting this in real apps
    upload_time = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.email} - {self.filename}"