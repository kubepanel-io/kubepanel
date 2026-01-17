"""
License Service

Provides license status checking by reading from the Kubernetes License CRD.
Results are cached to avoid excessive K8s API calls.
"""

import logging
from typing import Optional, Tuple
from datetime import datetime, timezone

from django.core.cache import cache
from kubernetes import client, config
from kubernetes.client.rest import ApiException

logger = logging.getLogger(__name__)

# =============================================================================
# Constants
# =============================================================================

LICENSE_CR_NAME = 'kubepanel-license'
LICENSE_GROUP = 'kubepanel.io'
LICENSE_VERSION = 'v1alpha1'
LICENSE_PLURAL = 'licenses'

CACHE_KEY = 'kubepanel_license_status'
CACHE_TTL = 300  # 5 minutes

# Default limits for community tier
COMMUNITY_MAX_DOMAINS = 5


class LicenseService:
    """
    Service for checking KubePanel license status.

    Reads license status from the Kubernetes License CRD and caches results.
    If no license is found, returns community tier defaults.
    """

    _k8s_configured = False

    @classmethod
    def _ensure_k8s_config(cls):
        """Ensure Kubernetes client is configured."""
        if not cls._k8s_configured:
            try:
                # Try in-cluster config first (when running in K8s)
                config.load_incluster_config()
            except config.ConfigException:
                try:
                    # Fall back to kubeconfig (for local development)
                    config.load_kube_config()
                except config.ConfigException:
                    logger.warning("Could not configure Kubernetes client")
                    return False
            cls._k8s_configured = True
        return True

    @classmethod
    def get_license_status(cls, use_cache: bool = True) -> dict:
        """
        Get current license status from Kubernetes CRD.

        Args:
            use_cache: Whether to use cached status (default True)

        Returns:
            Dictionary with license status fields:
            - valid: bool
            - tier: str (community, pro, premium, enterprise)
            - maxDomains: int (-1 for unlimited)
            - domainsUsed: int
            - customerName: str
            - expiresAt: str (ISO format)
            - lastPhoneHome: str (ISO format)
            - gracePeriodEndsAt: str or None
            - message: str
        """
        # Check cache first
        if use_cache:
            cached = cache.get(CACHE_KEY)
            if cached is not None:
                return cached

        # Default community status (used if no license CR exists)
        default_status = {
            'valid': True,
            'tier': 'community',
            'maxDomains': COMMUNITY_MAX_DOMAINS,
            'domainsUsed': 0,
            'customerName': '',
            'customerId': '',
            'expiresAt': None,
            'lastPhoneHome': None,
            'phoneHomeFailures': 0,
            'gracePeriodEndsAt': None,
            'message': 'No license installed - Community tier',
            'features': [],
        }

        # Try to read from Kubernetes
        if not cls._ensure_k8s_config():
            logger.warning("K8s not configured, using community defaults")
            cache.set(CACHE_KEY, default_status, CACHE_TTL)
            return default_status

        try:
            api = client.CustomObjectsApi()
            license_cr = api.get_cluster_custom_object(
                group=LICENSE_GROUP,
                version=LICENSE_VERSION,
                plural=LICENSE_PLURAL,
                name=LICENSE_CR_NAME
            )

            status = license_cr.get('status', {})

            # Merge with defaults for any missing fields
            result = {**default_status, **status}

            # If no license key in spec, it's community tier
            spec = license_cr.get('spec', {})
            if not spec.get('licenseKey'):
                result['tier'] = 'community'
                result['maxDomains'] = COMMUNITY_MAX_DOMAINS
                result['message'] = 'No license key configured - Community tier'

            cache.set(CACHE_KEY, result, CACHE_TTL)
            return result

        except ApiException as e:
            if e.status == 404:
                # License CR doesn't exist - community tier
                logger.info("No License CR found, using community tier")
                cache.set(CACHE_KEY, default_status, CACHE_TTL)
                return default_status
            else:
                logger.error(f"Error reading License CR: {e}")
                # On error, return cached or default (don't break the app)
                cache.set(CACHE_KEY, default_status, CACHE_TTL)
                return default_status

        except Exception as e:
            logger.error(f"Unexpected error reading license status: {e}")
            cache.set(CACHE_KEY, default_status, CACHE_TTL)
            return default_status

    @classmethod
    def invalidate_cache(cls):
        """Invalidate the cached license status."""
        cache.delete(CACHE_KEY)

    @classmethod
    def can_create_domain(cls) -> Tuple[bool, str]:
        """
        Check if a new domain can be created based on license limits.

        Returns:
            Tuple of (allowed: bool, message: str)
        """
        from dashboard.models import Domain

        status = cls.get_license_status()

        max_domains = status.get('maxDomains', COMMUNITY_MAX_DOMAINS)

        # -1 means unlimited
        if max_domains == -1:
            return True, ""

        current_count = Domain.objects.count()

        if current_count >= max_domains:
            tier = status.get('tier', 'community')
            return False, (
                f"Domain limit reached ({current_count}/{max_domains}). "
                f"Current tier: {tier}. Please upgrade your license."
            )

        return True, ""

    @classmethod
    def get_domain_usage(cls) -> dict:
        """
        Get domain usage statistics.

        Returns:
            Dictionary with usage info:
            - current: int (current domain count)
            - max: int (-1 for unlimited)
            - percentage: float (0-100, or 0 if unlimited)
        """
        from dashboard.models import Domain

        status = cls.get_license_status()
        max_domains = status.get('maxDomains', COMMUNITY_MAX_DOMAINS)
        current = Domain.objects.count()

        if max_domains == -1:
            percentage = 0
        else:
            percentage = (current / max_domains * 100) if max_domains > 0 else 0

        return {
            'current': current,
            'max': max_domains,
            'percentage': min(percentage, 100),
        }

    @classmethod
    def is_in_grace_period(cls) -> bool:
        """Check if license is currently in grace period."""
        status = cls.get_license_status()
        grace_end = status.get('gracePeriodEndsAt')

        if not grace_end:
            return False

        try:
            grace_end_dt = datetime.fromisoformat(grace_end.replace('Z', '+00:00'))
            return datetime.now(timezone.utc) < grace_end_dt
        except (ValueError, AttributeError):
            return False

    @classmethod
    def get_tier(cls) -> str:
        """Get the current license tier."""
        status = cls.get_license_status()
        return status.get('tier', 'community')

    @classmethod
    def is_pro_or_higher(cls) -> bool:
        """Check if license is Pro tier or higher."""
        tier = cls.get_tier()
        return tier in ('pro', 'premium', 'enterprise')
