"""
DKIM Key Generation Service

Generates RSA keypairs for DKIM email signing.
Keys are stored in Kubernetes Secrets (not Django DB).
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from typing import Tuple


def generate_dkim_keypair(
    key_size: int = 2048,
    selector: str = "default"
) -> Tuple[str, str, str]:
    """
    Generate a DKIM RSA keypair.

    Args:
        key_size: RSA key size in bits (default 2048)
        selector: DKIM selector name (default "default")

    Returns:
        Tuple of (private_key_pem, public_key_base64, dns_txt_record)
        - private_key_pem: PEM-encoded private key for signing
        - public_key_base64: Base64-encoded public key (no PEM headers)
        - dns_txt_record: Complete DKIM DNS TXT record value
    """
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    # Get public key
    public_key = private_key.public_key()

    # Serialize public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # Extract base64 portion (remove PEM headers and newlines)
    # PEM format: -----BEGIN PUBLIC KEY-----\n<base64>\n-----END PUBLIC KEY-----
    lines = public_pem.strip().split('\n')
    # Remove first (BEGIN) and last (END) lines, join the rest
    public_b64 = ''.join(lines[1:-1])

    # Create DNS TXT record value
    dns_txt = f"v=DKIM1; k=rsa; p={public_b64}"

    return private_pem, public_b64, dns_txt


def get_dkim_dns_name(selector: str = "default") -> str:
    """
    Get the DNS record name for a DKIM key.

    Args:
        selector: DKIM selector name

    Returns:
        DNS record name (without domain suffix)
    """
    return f"{selector}._domainkey"
