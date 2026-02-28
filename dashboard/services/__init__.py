"""
KubePanel Services

Business logic services for the dashboard.
"""

from .dkim import generate_dkim_keypair, get_dkim_dns_name

__all__ = [
    'generate_dkim_keypair',
    'get_dkim_dns_name',
]
