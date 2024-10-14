


# from django.db import models
# from django.contrib.auth.models import User
# from cryptography.fernet import Fernet
# from django.conf import settings
# from django.core.exceptions import ValidationError
# from django.utils import timezone

# # Fetch the Fernet key from settings
# cipher = Fernet(settings.FERNET_KEY.encode())

# class EncryptedBlock(models.Model):
#     first_name = models.TextField()
#     last_name = models.TextField()
#     data = models.TextField()

#     def save(self, *args, **kwargs):
#         if isinstance(self.first_name, str):
#             self.first_name = cipher.encrypt(self.first_name.encode()).decode()
#         if isinstance(self.last_name, str):
#             self.last_name = cipher.encrypt(self.last_name.encode()).decode()
#         if isinstance(self.data, str):
#             self.data = cipher.encrypt(self.data.encode()).decode()

#         super().save(*args, **kwargs)

#     def decrypt_fields(self):
#         try:
#             return {
#                 'first_name': cipher.decrypt(self.first_name.encode()).decode(),
#                 'last_name': cipher.decrypt(self.last_name.encode()).decode(),
#                 'data': cipher.decrypt(self.data.encode()).decode(),
#             }
#         except Exception as e:
#             raise ValidationError(f"Error decrypting data: {e}")

#     def __str__(self):
#         try:
#             decrypted_data = self.decrypt_fields()
#             return f"EncryptedBlock({decrypted_data['first_name']} {decrypted_data['last_name']})"
#         except ValidationError as e:
#             return f"Error: {e}"

# # Define OTP model
# class OTP(models.Model):
#     user = models.ForeignKey(User, on_delete=models.CASCADE)  # Links to a user
#     code = models.CharField(max_length=6)  # Store 6 digit OTP code
#     created_at = models.DateTimeField(auto_now_add=True)  # Timestamp when OTP was created

#     def is_expired(self):
#         """
#         Returns True if the OTP is older than 10 minutes.
#         """
#         return timezone.now() > (self.created_at + timezone.timedelta(minutes=10))

#     def __str__(self):
#         return f"OTP({self.user.username}): {self.code}"




from django.db import models
from django.contrib.auth.models import User
from cryptography.fernet import Fernet
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone

# Fetch the Fernet key from settings
cipher = Fernet(settings.FERNET_KEY.encode())

class EncryptedBlock(models.Model):
    """
    Model to store encrypted first name, last name, and data. Automatically encrypts before saving,
    and provides a method to decrypt the data when needed.
    """
    first_name = models.TextField()
    last_name = models.TextField()
    data = models.TextField()

    def save(self, *args, **kwargs):
        """
        Override the save method to ensure that data is encrypted before saving.
        """
        if isinstance(self.first_name, str):
            self.first_name = cipher.encrypt(self.first_name.encode()).decode()
        if isinstance(self.last_name, str):
            self.last_name = cipher.encrypt(self.last_name.encode()).decode()
        if isinstance(self.data, str):
            self.data = cipher.encrypt(self.data.encode()).decode()

        super().save(*args, **kwargs)

    def decrypt_fields(self):
        """
        Decrypts the encrypted fields and returns them as a dictionary.
        """
        try:
            decrypted_first_name = cipher.decrypt(self.first_name.encode()).decode()
            decrypted_last_name = cipher.decrypt(self.last_name.encode()).decode()
            decrypted_data = cipher.decrypt(self.data.encode()).decode()

            return {
                'first_name': decrypted_first_name,
                'last_name': decrypted_last_name,
                'data': decrypted_data,
            }
        except Exception as e:
            raise ValidationError(f"Error decrypting data: {e}")

    def __str__(self):
        """
        Returns a string representation of the decrypted block, or an error message if decryption fails.
        """
        try:
            decrypted_data = self.decrypt_fields()
            return f"EncryptedBlock({decrypted_data['first_name']} {decrypted_data['last_name']})"
        except ValidationError as e:
            return f"Error: {e}"

class OTP(models.Model):
    """
    Model to store OTPs (One-Time Passwords) for user verification. Each OTP is associated with a User
    and has an expiration time of 10 minutes from creation.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # Links to a user
    code = models.CharField(max_length=6)  # Store 6 digit OTP code
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp when OTP was created

    def is_expired(self):
        """
        Check if the OTP has expired (older than 10 minutes).
        """
        return timezone.now() > (self.created_at + timezone.timedelta(minutes=10))

    def __str__(self):
        """
        Return the OTP with the associated username for easy identification.
        """
        return f"OTP({self.user.username}): {self.code}"

class Block(models.Model):
    """
    Model to store individual blocks in a blockchain.
    Each block contains an index, timestamp, encrypted data, and references to the previous block.
    """
    index = models.IntegerField()  # Index of the block in the chain
    timestamp = models.DateTimeField(auto_now_add=True)  # When the block was created
    data = models.TextField()  # Encrypted data stored in the block
    previous_hash = models.CharField(max_length=256)  # Hash of the previous block
    current_hash = models.CharField(max_length=256)  # Hash of the current block
    nonce = models.IntegerField(default=0)  # Nonce for Proof of Work

    def __str__(self):
        """
        Returns a string representation of the block with its index and current hash.
        """
        return f"Block {self.index} - Hash: {self.current_hash}"

