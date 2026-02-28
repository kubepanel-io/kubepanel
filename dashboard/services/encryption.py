"""
Encryption Service

Provides secure encryption/decryption for sensitive data like API tokens.
Uses Django's Fernet-based signing with additional encryption layer.
"""

import base64
import hashlib
import logging
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.signing import Signer, BadSignature

logger = logging.getLogger(__name__)


def _get_encryption_key() -> bytes:
    """
    Derive a Fernet-compatible encryption key from Django's SECRET_KEY.

    Returns:
        32-byte base64-encoded key suitable for Fernet
    """
    # Use SHA256 to derive a consistent 32-byte key from SECRET_KEY
    secret = settings.SECRET_KEY.encode('utf-8')
    key_bytes = hashlib.sha256(secret).digest()
    return base64.urlsafe_b64encode(key_bytes)


def _get_fernet() -> Fernet:
    """Get a Fernet instance for encryption/decryption."""
    return Fernet(_get_encryption_key())


def encrypt_token(plaintext: str) -> str:
    """
    Encrypt a sensitive string (like an API token).

    Uses Fernet symmetric encryption with a key derived from Django's SECRET_KEY.
    The encrypted data is then signed to detect tampering.

    Args:
        plaintext: The string to encrypt

    Returns:
        Encrypted and signed string (safe for database storage)
    """
    if not plaintext:
        return ''

    try:
        fernet = _get_fernet()
        encrypted = fernet.encrypt(plaintext.encode('utf-8'))

        # Sign the encrypted data to detect tampering
        signer = Signer()
        signed = signer.sign(encrypted.decode('utf-8'))

        return signed
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        raise ValueError("Failed to encrypt token") from e


def decrypt_token(encrypted: str) -> str:
    """
    Decrypt an encrypted token.

    Args:
        encrypted: The encrypted and signed string

    Returns:
        Original plaintext string

    Raises:
        ValueError: If decryption fails (invalid signature or corrupted data)
    """
    if not encrypted:
        return ''

    try:
        # Verify signature
        signer = Signer()
        unsigned = signer.unsign(encrypted)

        # Decrypt
        fernet = _get_fernet()
        decrypted = fernet.decrypt(unsigned.encode('utf-8'))

        return decrypted.decode('utf-8')
    except BadSignature:
        logger.error("Token signature verification failed")
        raise ValueError("Invalid token signature - data may have been tampered with")
    except InvalidToken:
        logger.error("Token decryption failed")
        raise ValueError("Failed to decrypt token - invalid or corrupted data")
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise ValueError("Failed to decrypt token") from e


def is_encrypted(value: str) -> bool:
    """
    Check if a value appears to be encrypted.

    This checks for the signature format used by Django's Signer.

    Args:
        value: String to check

    Returns:
        True if the value appears to be encrypted
    """
    if not value:
        return False

    # Django Signer uses ':' as separator
    # Format is: data:signature
    return ':' in value and len(value) > 50


def rotate_encryption(old_encrypted: str, old_secret_key: str = None) -> str:
    """
    Re-encrypt a token with the current SECRET_KEY.

    Useful when rotating SECRET_KEY or migrating data.

    Args:
        old_encrypted: Token encrypted with old key
        old_secret_key: The old SECRET_KEY (if different from current)

    Returns:
        Token encrypted with current key
    """
    # For now, just decrypt and re-encrypt
    # In a real implementation, you'd use the old_secret_key
    # to derive the old encryption key
    plaintext = decrypt_token(old_encrypted)
    return encrypt_token(plaintext)


class EncryptedField:
    """
    Descriptor for model fields that should be encrypted.

    Usage:
        class MyModel(models.Model):
            _api_token = models.CharField(max_length=500)
            api_token = EncryptedField('_api_token')

            # Or use as a property manually in save/load
    """

    def __init__(self, field_name: str):
        self.field_name = field_name

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        encrypted = getattr(obj, self.field_name, '')
        if encrypted and is_encrypted(encrypted):
            try:
                return decrypt_token(encrypted)
            except ValueError:
                logger.warning(f"Failed to decrypt {self.field_name}")
                return ''
        return encrypted

    def __set__(self, obj, value):
        if value and not is_encrypted(value):
            value = encrypt_token(value)
        setattr(obj, self.field_name, value)
