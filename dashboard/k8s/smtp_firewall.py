"""
SMTPFirewall CR Operations

CRUD operations for SMTPFirewall custom resources in Kubernetes.
SMTPFirewall CRs manage rspamd blocking rules and per-user rate limits.
"""

from kubernetes.client.rest import ApiException
from typing import Optional, List
from dataclasses import dataclass, field
import logging

from .client import (
    get_custom_api,
    handle_api_exception,
    K8sNotFoundError,
    K8sClientError,
)

logger = logging.getLogger(__name__)

# SMTPFirewall CRD constants
SMTPFIREWALL_GROUP = "kubepanel.io"
SMTPFIREWALL_VERSION = "v1alpha1"
SMTPFIREWALL_PLURAL = "smtpfirewalls"

# Default CR name (singleton pattern)
DEFAULT_SMTPFIREWALL_NAME = "default"


@dataclass
class RateLimit:
    """Per-user rate limit."""
    user: str
    rate: str

    def to_dict(self) -> dict:
        return {"user": self.user, "rate": self.rate}

    @classmethod
    def from_dict(cls, d: dict) -> "RateLimit":
        return cls(user=d.get("user", ""), rate=d.get("rate", ""))


class SMTPFirewallStatus:
    """
    Parsed SMTPFirewall CR status.

    Provides easy access to status fields.
    """

    def __init__(self, status_dict: dict):
        self._raw = status_dict or {}

    @property
    def phase(self) -> str:
        return self._raw.get("phase", "Unknown")

    @property
    def message(self) -> str:
        return self._raw.get("message", "")

    @property
    def blocked_senders_count(self) -> int:
        return self._raw.get("blockedSendersCount", 0)

    @property
    def blocked_domains_count(self) -> int:
        return self._raw.get("blockedDomainsCount", 0)

    @property
    def blocked_ips_count(self) -> int:
        return self._raw.get("blockedIPsCount", 0)

    @property
    def rate_limits_count(self) -> int:
        return self._raw.get("rateLimitsCount", 0)

    @property
    def is_active(self) -> bool:
        return self.phase == "Active"

    @property
    def is_syncing(self) -> bool:
        return self.phase == "Syncing"

    @property
    def is_failed(self) -> bool:
        return self.phase == "Failed"

    @property
    def last_synced_at(self) -> Optional[str]:
        return self._raw.get("lastSyncedAt")


class SMTPFirewall:
    """
    SMTPFirewall CR wrapper.

    Represents a SMTPFirewall custom resource with easy access to spec and status.
    """

    def __init__(self, cr_dict: dict):
        self._raw = cr_dict

    @property
    def name(self) -> str:
        """CR metadata name."""
        return self._raw.get("metadata", {}).get("name", "")

    @property
    def spec(self) -> dict:
        """Raw spec dict."""
        return self._raw.get("spec", {})

    @property
    def status(self) -> SMTPFirewallStatus:
        """Parsed status."""
        return SMTPFirewallStatus(self._raw.get("status"))

    @property
    def blocked_senders(self) -> List[str]:
        """List of blocked sender email addresses."""
        return self._raw.get("spec", {}).get("blockedSenders", [])

    @property
    def blocked_domains(self) -> List[str]:
        """List of blocked sender domains."""
        return self._raw.get("spec", {}).get("blockedDomains", [])

    @property
    def blocked_ips(self) -> List[str]:
        """List of blocked IP addresses."""
        return self._raw.get("spec", {}).get("blockedIPs", [])

    @property
    def rate_limits(self) -> List[RateLimit]:
        """List of per-user rate limits."""
        return [
            RateLimit.from_dict(rl)
            for rl in self._raw.get("spec", {}).get("rateLimits", [])
        ]

    @property
    def generation(self) -> int:
        return self._raw.get("metadata", {}).get("generation", 0)

    @property
    def creation_timestamp(self) -> str:
        return self._raw.get("metadata", {}).get("creationTimestamp", "")

    def to_dict(self) -> dict:
        """Return raw CR dict."""
        return self._raw


# =============================================================================
# CRUD Operations
# =============================================================================

def get_smtp_firewall(name: str = DEFAULT_SMTPFIREWALL_NAME) -> SMTPFirewall:
    """
    Get a SMTPFirewall CR by name.

    Args:
        name: The CR name (default: 'default')

    Returns:
        SMTPFirewall object

    Raises:
        K8sNotFoundError: If CR not found
        K8sClientError: For other K8s errors
    """
    custom_api = get_custom_api()

    try:
        result = custom_api.get_cluster_custom_object(
            group=SMTPFIREWALL_GROUP,
            version=SMTPFIREWALL_VERSION,
            plural=SMTPFIREWALL_PLURAL,
            name=name,
        )
        return SMTPFirewall(result)
    except ApiException as e:
        handle_api_exception(e, f"SMTPFirewall '{name}'")


def smtp_firewall_exists(name: str = DEFAULT_SMTPFIREWALL_NAME) -> bool:
    """
    Check if a SMTPFirewall exists.

    Args:
        name: The CR name to check

    Returns:
        True if exists, False otherwise
    """
    try:
        get_smtp_firewall(name)
        return True
    except K8sNotFoundError:
        return False


def create_smtp_firewall(
    name: str = DEFAULT_SMTPFIREWALL_NAME,
    blocked_senders: Optional[List[str]] = None,
    blocked_domains: Optional[List[str]] = None,
    blocked_ips: Optional[List[str]] = None,
    rate_limits: Optional[List[RateLimit]] = None,
    labels: Optional[dict] = None,
) -> SMTPFirewall:
    """
    Create a new SMTPFirewall CR.

    Args:
        name: CR name (default: 'default')
        blocked_senders: List of sender emails to block
        blocked_domains: List of domains to block
        blocked_ips: List of IPs to block
        rate_limits: List of per-user rate limits
        labels: Additional labels

    Returns:
        Created SMTPFirewall object

    Raises:
        K8sConflictError: If CR already exists
        K8sValidationError: If spec is invalid
        K8sClientError: For other K8s errors
    """
    custom_api = get_custom_api()

    # Build labels
    all_labels = {
        "app.kubernetes.io/managed-by": "kubepanel",
    }
    if labels:
        all_labels.update(labels)

    # Build spec
    spec = {}
    if blocked_senders:
        spec["blockedSenders"] = blocked_senders
    if blocked_domains:
        spec["blockedDomains"] = blocked_domains
    if blocked_ips:
        spec["blockedIPs"] = blocked_ips
    if rate_limits:
        spec["rateLimits"] = [rl.to_dict() for rl in rate_limits]

    # Build CR
    smtp_firewall_cr = {
        "apiVersion": f"{SMTPFIREWALL_GROUP}/{SMTPFIREWALL_VERSION}",
        "kind": "SMTPFirewall",
        "metadata": {
            "name": name,
            "labels": all_labels,
        },
        "spec": spec,
    }

    logger.info(f"Creating SMTPFirewall CR '{name}'")

    try:
        result = custom_api.create_cluster_custom_object(
            group=SMTPFIREWALL_GROUP,
            version=SMTPFIREWALL_VERSION,
            plural=SMTPFIREWALL_PLURAL,
            body=smtp_firewall_cr,
        )
        logger.info(f"Created SMTPFirewall CR '{name}'")
        return SMTPFirewall(result)
    except ApiException as e:
        handle_api_exception(e, f"SMTPFirewall '{name}'")


def delete_smtp_firewall(name: str = DEFAULT_SMTPFIREWALL_NAME) -> None:
    """
    Delete a SMTPFirewall CR.

    The operator will clear the rspamd map files.

    Args:
        name: The CR name to delete

    Raises:
        K8sNotFoundError: If CR not found
        K8sClientError: For other K8s errors
    """
    custom_api = get_custom_api()

    logger.info(f"Deleting SMTPFirewall CR '{name}'")

    try:
        custom_api.delete_cluster_custom_object(
            group=SMTPFIREWALL_GROUP,
            version=SMTPFIREWALL_VERSION,
            plural=SMTPFIREWALL_PLURAL,
            name=name,
        )
        logger.info(f"Deleted SMTPFirewall CR '{name}'")
    except ApiException as e:
        handle_api_exception(e, f"SMTPFirewall '{name}'")


def patch_smtp_firewall(
    name: str = DEFAULT_SMTPFIREWALL_NAME,
    blocked_senders: Optional[List[str]] = None,
    blocked_domains: Optional[List[str]] = None,
    blocked_ips: Optional[List[str]] = None,
    rate_limits: Optional[List[RateLimit]] = None,
) -> SMTPFirewall:
    """
    Patch SMTPFirewall CR spec.

    Args:
        name: The CR name
        blocked_senders: Complete list of blocked senders (None = don't change)
        blocked_domains: Complete list of blocked domains (None = don't change)
        blocked_ips: Complete list of blocked IPs (None = don't change)
        rate_limits: Complete list of rate limits (None = don't change)

    Returns:
        Updated SMTPFirewall object

    Raises:
        K8sNotFoundError: If CR not found
        K8sClientError: For other K8s errors
    """
    custom_api = get_custom_api()

    patch_body = {"spec": {}}

    if blocked_senders is not None:
        patch_body["spec"]["blockedSenders"] = blocked_senders
    if blocked_domains is not None:
        patch_body["spec"]["blockedDomains"] = blocked_domains
    if blocked_ips is not None:
        patch_body["spec"]["blockedIPs"] = blocked_ips
    if rate_limits is not None:
        patch_body["spec"]["rateLimits"] = [rl.to_dict() for rl in rate_limits]

    if not patch_body["spec"]:
        # Nothing to patch
        return get_smtp_firewall(name)

    logger.info(f"Patching SMTPFirewall CR '{name}'")

    try:
        result = custom_api.patch_cluster_custom_object(
            group=SMTPFIREWALL_GROUP,
            version=SMTPFIREWALL_VERSION,
            plural=SMTPFIREWALL_PLURAL,
            name=name,
            body=patch_body,
        )
        logger.info(f"Patched SMTPFirewall CR '{name}'")
        return SMTPFirewall(result)
    except ApiException as e:
        handle_api_exception(e, f"SMTPFirewall '{name}'")


def get_or_create_smtp_firewall(name: str = DEFAULT_SMTPFIREWALL_NAME) -> SMTPFirewall:
    """
    Get existing SMTPFirewall or create new one.

    Args:
        name: CR name (default: 'default')

    Returns:
        SMTPFirewall object
    """
    try:
        return get_smtp_firewall(name)
    except K8sNotFoundError:
        return create_smtp_firewall(name=name)


# =============================================================================
# Convenience functions for blocked senders
# =============================================================================

def add_blocked_sender(sender: str, name: str = DEFAULT_SMTPFIREWALL_NAME) -> SMTPFirewall:
    """Add a sender to the blocked list."""
    fw = get_or_create_smtp_firewall(name)
    senders = list(fw.blocked_senders)
    sender = sender.lower().strip()
    if sender not in senders:
        senders.append(sender)
        return patch_smtp_firewall(name, blocked_senders=senders)
    return fw


def remove_blocked_sender(sender: str, name: str = DEFAULT_SMTPFIREWALL_NAME) -> SMTPFirewall:
    """Remove a sender from the blocked list."""
    fw = get_or_create_smtp_firewall(name)
    senders = list(fw.blocked_senders)
    sender = sender.lower().strip()
    if sender in senders:
        senders.remove(sender)
        return patch_smtp_firewall(name, blocked_senders=senders)
    return fw


# =============================================================================
# Convenience functions for blocked domains
# =============================================================================

def add_blocked_domain(domain: str, name: str = DEFAULT_SMTPFIREWALL_NAME) -> SMTPFirewall:
    """Add a domain to the blocked list."""
    fw = get_or_create_smtp_firewall(name)
    domains = list(fw.blocked_domains)
    domain = domain.lower().strip()
    if domain not in domains:
        domains.append(domain)
        return patch_smtp_firewall(name, blocked_domains=domains)
    return fw


def remove_blocked_domain(domain: str, name: str = DEFAULT_SMTPFIREWALL_NAME) -> SMTPFirewall:
    """Remove a domain from the blocked list."""
    fw = get_or_create_smtp_firewall(name)
    domains = list(fw.blocked_domains)
    domain = domain.lower().strip()
    if domain in domains:
        domains.remove(domain)
        return patch_smtp_firewall(name, blocked_domains=domains)
    return fw


# =============================================================================
# Convenience functions for blocked IPs
# =============================================================================

def add_blocked_ip(ip: str, name: str = DEFAULT_SMTPFIREWALL_NAME) -> SMTPFirewall:
    """Add an IP to the blocked list."""
    fw = get_or_create_smtp_firewall(name)
    ips = list(fw.blocked_ips)
    ip = ip.strip()
    if ip not in ips:
        ips.append(ip)
        return patch_smtp_firewall(name, blocked_ips=ips)
    return fw


def remove_blocked_ip(ip: str, name: str = DEFAULT_SMTPFIREWALL_NAME) -> SMTPFirewall:
    """Remove an IP from the blocked list."""
    fw = get_or_create_smtp_firewall(name)
    ips = list(fw.blocked_ips)
    ip = ip.strip()
    if ip in ips:
        ips.remove(ip)
        return patch_smtp_firewall(name, blocked_ips=ips)
    return fw


# =============================================================================
# Convenience functions for rate limits
# =============================================================================

def add_rate_limit(user: str, rate: str, name: str = DEFAULT_SMTPFIREWALL_NAME) -> SMTPFirewall:
    """Add or update a per-user rate limit."""
    fw = get_or_create_smtp_firewall(name)
    rate_limits = list(fw.rate_limits)
    user = user.lower().strip()

    # Remove existing rate limit for this user if any
    rate_limits = [rl for rl in rate_limits if rl.user != user]

    # Add new rate limit
    rate_limits.append(RateLimit(user=user, rate=rate))

    return patch_smtp_firewall(name, rate_limits=rate_limits)


def remove_rate_limit(user: str, name: str = DEFAULT_SMTPFIREWALL_NAME) -> SMTPFirewall:
    """Remove a per-user rate limit."""
    fw = get_or_create_smtp_firewall(name)
    rate_limits = list(fw.rate_limits)
    user = user.lower().strip()

    # Remove rate limit for this user
    new_limits = [rl for rl in rate_limits if rl.user != user]

    if len(new_limits) != len(rate_limits):
        return patch_smtp_firewall(name, rate_limits=new_limits)
    return fw


def get_rate_limit(user: str, name: str = DEFAULT_SMTPFIREWALL_NAME) -> Optional[RateLimit]:
    """Get the rate limit for a specific user."""
    fw = get_or_create_smtp_firewall(name)
    user = user.lower().strip()

    for rl in fw.rate_limits:
        if rl.user == user:
            return rl
    return None


def get_all_rate_limits(name: str = DEFAULT_SMTPFIREWALL_NAME) -> List[RateLimit]:
    """Get all rate limits."""
    fw = get_or_create_smtp_firewall(name)
    return fw.rate_limits
