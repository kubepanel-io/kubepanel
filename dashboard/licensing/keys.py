"""
License Key Verification

Ed25519 signature verification for KubePanel license keys.
License keys are in the format: base64(json_payload).base64(signature)
"""

import base64
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)

# =============================================================================
# PUBLIC KEY
# =============================================================================
# This is the public key used to verify license signatures.
# The corresponding private key is kept secret and used only for license generation.
#
# TO GENERATE A NEW KEYPAIR (do this once, keep private key secret):
#   from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
#   from cryptography.hazmat.primitives import serialization
#
#   private_key = Ed25519PrivateKey.generate()
#   public_key = private_key.public_key()
#
#   # Save private key (KEEP SECRET!)
#   private_pem = private_key.private_bytes(
#       encoding=serialization.Encoding.PEM,
#       format=serialization.PrivateFormat.PKCS8,
#       encryption_algorithm=serialization.NoEncryption()
#   )
#
#   # Save public key (embed in code)
#   public_pem = public_key.public_bytes(
#       encoding=serialization.Encoding.PEM,
#       format=serialization.PublicFormat.SubjectPublicKeyInfo
#   )
# =============================================================================

PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END PUBLIC KEY-----"""

# TODO: Replace the above with your actual public key after generating a keypair


def get_public_key() -> Ed25519PublicKey:
    """Load and return the embedded public key."""
    return load_pem_public_key(PUBLIC_KEY_PEM)


def _add_base64_padding(data: str) -> str:
    """Add padding to base64 string if needed."""
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return data


def verify_license_key(license_key: str) -> Optional[dict]:
    """
    Verify a license key signature and return the payload.

    Args:
        license_key: The license key in format "base64(payload).base64(signature)"

    Returns:
        The decoded payload dict if valid, None if invalid or expired.
    """
    if not license_key or '.' not in license_key:
        logger.debug("License key missing or invalid format")
        return None

    try:
        # Split into payload and signature
        parts = license_key.rsplit('.', 1)
        if len(parts) != 2:
            logger.debug("License key does not have exactly 2 parts")
            return None

        payload_b64, sig_b64 = parts

        # Decode base64 (handle URL-safe encoding and missing padding)
        payload_bytes = base64.urlsafe_b64decode(_add_base64_padding(payload_b64))
        signature = base64.urlsafe_b64decode(_add_base64_padding(sig_b64))

        # Verify signature
        public_key = get_public_key()
        public_key.verify(signature, payload_bytes)

        # Parse payload
        payload = json.loads(payload_bytes.decode('utf-8'))

        # Validate required fields
        required_fields = ['iss', 'sub', 'tier', 'exp']
        for field in required_fields:
            if field not in payload:
                logger.warning(f"License payload missing required field: {field}")
                return None

        # Check issuer
        if payload.get('iss') != 'kubepanel.io':
            logger.warning(f"Invalid license issuer: {payload.get('iss')}")
            return None

        # Check expiration (but don't reject - let caller decide)
        exp_timestamp = payload.get('exp', 0)
        exp_datetime = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
        payload['_expired'] = datetime.now(timezone.utc) > exp_datetime
        payload['_expires_at'] = exp_datetime

        logger.debug(f"License key verified for customer: {payload.get('sub')}")
        return payload

    except InvalidSignature:
        logger.warning("License key signature verification failed")
        return None
    except json.JSONDecodeError as e:
        logger.warning(f"License payload is not valid JSON: {e}")
        return None
    except Exception as e:
        logger.warning(f"License key verification failed: {e}")
        return None


def is_license_expired(payload: dict) -> bool:
    """Check if a verified license payload is expired."""
    return payload.get('_expired', True)


def get_license_tier(payload: dict) -> str:
    """Get the tier from a verified license payload."""
    return payload.get('tier', 'community')


def get_max_domains(payload: dict) -> int:
    """Get the max domains from a verified license payload. -1 means unlimited."""
    return payload.get('max_domains', 5)
