"""
DNSZone CR Operations

CRUD operations for DNSZone custom resources in Kubernetes.
DNSZone CRs manage DNS zones and records in Cloudflare.
"""

from kubernetes.client.rest import ApiException
from typing import Optional
import logging
import re

from .client import (
    get_custom_api,
    handle_api_exception,
    K8sNotFoundError,
    K8sClientError,
)

logger = logging.getLogger(__name__)

# DNSZone CRD constants
DNSZONE_GROUP = "kubepanel.io"
DNSZONE_VERSION = "v1alpha1"
DNSZONE_PLURAL = "dnszones"


def _sanitize_cr_name(domain_name: str) -> str:
    """
    Convert domain name to a valid CR name.

    e.g., 'example.com' -> 'example-com'
    e.g., 'my.sub.domain.com' -> 'my-sub-domain-com'
    """
    sanitized = re.sub(r'[^a-z0-9-]', '-', domain_name.lower())
    sanitized = re.sub(r'-+', '-', sanitized)  # collapse multiple dashes
    return sanitized.strip('-')


class DNSZoneStatus:
    """
    Parsed DNSZone CR status.

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
    def zone_id(self) -> Optional[str]:
        return self._raw.get("zoneId")

    @property
    def record_count(self) -> int:
        return self._raw.get("recordCount", 0)

    @property
    def is_ready(self) -> bool:
        return self.phase == "Ready"

    @property
    def is_syncing(self) -> bool:
        return self.phase == "Syncing"

    @property
    def is_failed(self) -> bool:
        return self.phase == "Failed"

    @property
    def records(self) -> list[dict]:
        """Status records with sync state."""
        return self._raw.get("records", [])

    @property
    def last_synced_at(self) -> Optional[str]:
        return self._raw.get("lastSyncedAt")


class DNSZone:
    """
    DNSZone CR wrapper.

    Represents a DNSZone custom resource with easy access to spec and status.
    """

    def __init__(self, cr_dict: dict):
        self._raw = cr_dict

    @property
    def name(self) -> str:
        """CR metadata name."""
        return self._raw.get("metadata", {}).get("name", "")

    @property
    def zone_name(self) -> str:
        """Zone name from spec."""
        return self._raw.get("spec", {}).get("zoneName", "")

    @property
    def spec(self) -> dict:
        """Raw spec dict."""
        return self._raw.get("spec", {})

    @property
    def status(self) -> DNSZoneStatus:
        """Parsed status."""
        return DNSZoneStatus(self._raw.get("status"))

    @property
    def records(self) -> list[dict]:
        """DNS records from spec (source of truth)."""
        return self._raw.get("spec", {}).get("records", [])

    @property
    def credential_secret_ref(self) -> Optional[dict]:
        """Cloudflare credential secret reference."""
        return self._raw.get("spec", {}).get("credentialSecretRef")

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

def create_dnszone(
    zone_name: str,
    credential_secret_ref: dict,
    records: Optional[list] = None,
    labels: Optional[dict] = None,
) -> DNSZone:
    """
    Create a new DNSZone CR.

    Args:
        zone_name: DNS zone name (e.g., 'example.com')
        credential_secret_ref: Dict with 'name' and 'namespace' for CF token secret
        records: Optional list of DNS records
        labels: Additional labels to add

    Returns:
        Created DNSZone object

    Raises:
        K8sConflictError: If zone already exists
        K8sValidationError: If spec is invalid
        K8sClientError: For other K8s errors
    """
    custom_api = get_custom_api()
    cr_name = _sanitize_cr_name(zone_name)

    # Build labels
    all_labels = {
        "app.kubernetes.io/managed-by": "kubepanel",
    }
    if labels:
        all_labels.update(labels)

    # Build spec
    spec = {
        "zoneName": zone_name,
        "credentialSecretRef": credential_secret_ref,
    }
    if records:
        spec["records"] = records

    # Build CR
    dnszone_cr = {
        "apiVersion": f"{DNSZONE_GROUP}/{DNSZONE_VERSION}",
        "kind": "DNSZone",
        "metadata": {
            "name": cr_name,
            "labels": all_labels,
        },
        "spec": spec,
    }

    logger.info(f"Creating DNSZone CR '{cr_name}' for zone '{zone_name}'")

    try:
        result = custom_api.create_cluster_custom_object(
            group=DNSZONE_GROUP,
            version=DNSZONE_VERSION,
            plural=DNSZONE_PLURAL,
            body=dnszone_cr,
        )
        logger.info(f"Created DNSZone CR '{cr_name}'")
        return DNSZone(result)
    except ApiException as e:
        handle_api_exception(e, f"DNSZone '{zone_name}'")


def get_dnszone(zone_name: str) -> DNSZone:
    """
    Get a DNSZone CR by zone name.

    Args:
        zone_name: The zone name (e.g., 'example.com')

    Returns:
        DNSZone object

    Raises:
        K8sNotFoundError: If zone not found
        K8sClientError: For other K8s errors
    """
    custom_api = get_custom_api()
    cr_name = _sanitize_cr_name(zone_name)

    try:
        result = custom_api.get_cluster_custom_object(
            group=DNSZONE_GROUP,
            version=DNSZONE_VERSION,
            plural=DNSZONE_PLURAL,
            name=cr_name,
        )
        return DNSZone(result)
    except ApiException as e:
        handle_api_exception(e, f"DNSZone '{zone_name}'")


def dnszone_exists(zone_name: str) -> bool:
    """
    Check if a DNSZone exists.

    Args:
        zone_name: The zone name to check

    Returns:
        True if exists, False otherwise
    """
    try:
        get_dnszone(zone_name)
        return True
    except K8sNotFoundError:
        return False


def delete_dnszone(zone_name: str) -> None:
    """
    Delete a DNSZone CR.

    The operator will handle cleanup of DNS records in Cloudflare.

    Args:
        zone_name: The zone name to delete

    Raises:
        K8sNotFoundError: If zone not found
        K8sClientError: For other K8s errors
    """
    custom_api = get_custom_api()
    cr_name = _sanitize_cr_name(zone_name)

    logger.info(f"Deleting DNSZone CR '{cr_name}'")

    try:
        custom_api.delete_cluster_custom_object(
            group=DNSZONE_GROUP,
            version=DNSZONE_VERSION,
            plural=DNSZONE_PLURAL,
            name=cr_name,
        )
        logger.info(f"Deleted DNSZone CR '{cr_name}'")
    except ApiException as e:
        handle_api_exception(e, f"DNSZone '{zone_name}'")


def patch_dnszone_records(zone_name: str, records: list) -> DNSZone:
    """
    Update DNS records in DNSZone CR spec.

    Args:
        zone_name: The zone name
        records: Complete list of DNS records

    Returns:
        Updated DNSZone object

    Raises:
        K8sNotFoundError: If zone not found
        K8sClientError: For other K8s errors
    """
    custom_api = get_custom_api()
    cr_name = _sanitize_cr_name(zone_name)

    patch_body = {"spec": {"records": records}}

    logger.info(f"Patching DNSZone CR '{cr_name}' with {len(records)} records")

    try:
        result = custom_api.patch_cluster_custom_object(
            group=DNSZONE_GROUP,
            version=DNSZONE_VERSION,
            plural=DNSZONE_PLURAL,
            name=cr_name,
            body=patch_body,
        )
        logger.info(f"Patched DNSZone CR '{cr_name}'")
        return DNSZone(result)
    except ApiException as e:
        handle_api_exception(e, f"DNSZone '{zone_name}'")


def add_dns_record(zone_name: str, record: dict) -> DNSZone:
    """
    Add a DNS record to DNSZone CR spec.

    Args:
        zone_name: The zone name
        record: Record dict with type, name, content, ttl, proxied, priority

    Returns:
        Updated DNSZone object
    """
    dnszone = get_dnszone(zone_name)
    records = list(dnszone.records)
    records.append(record)
    return patch_dnszone_records(zone_name, records)


def update_dns_record(zone_name: str, record_index: int, record: dict) -> DNSZone:
    """
    Update a DNS record in DNSZone CR spec.

    Args:
        zone_name: The zone name
        record_index: Index of the record in spec.records
        record: Updated record dict (should preserve recordId if present)

    Returns:
        Updated DNSZone object
    """
    dnszone = get_dnszone(zone_name)
    records = list(dnszone.records)

    if 0 <= record_index < len(records):
        # Preserve recordId from existing record if not in new record
        existing_record_id = records[record_index].get('recordId')
        if existing_record_id and 'recordId' not in record:
            record['recordId'] = existing_record_id
        records[record_index] = record
    else:
        raise K8sClientError(f"Record index {record_index} out of range")

    return patch_dnszone_records(zone_name, records)


def delete_dns_record(zone_name: str, record_index: int) -> DNSZone:
    """
    Delete a DNS record from DNSZone CR spec.

    The operator will delete the record from Cloudflare.

    Args:
        zone_name: The zone name
        record_index: Index of the record to delete

    Returns:
        Updated DNSZone object
    """
    dnszone = get_dnszone(zone_name)
    records = list(dnszone.records)

    if 0 <= record_index < len(records):
        deleted = records.pop(record_index)
        logger.info(f"Removing record {deleted.get('type')} {deleted.get('name')} from zone {zone_name}")
    else:
        raise K8sClientError(f"Record index {record_index} out of range")

    return patch_dnszone_records(zone_name, records)


def get_dns_records(zone_name: str) -> list[dict]:
    """
    Get DNS records from DNSZone CR spec.

    Args:
        zone_name: The zone name

    Returns:
        List of record dicts from spec
    """
    dnszone = get_dnszone(zone_name)
    return dnszone.records


def get_dns_record(zone_name: str, record_index: int) -> Optional[dict]:
    """
    Get a single DNS record by index.

    Args:
        zone_name: The zone name
        record_index: Index of the record

    Returns:
        Record dict or None if index out of range
    """
    records = get_dns_records(zone_name)
    if 0 <= record_index < len(records):
        return records[record_index]
    return None


def get_dns_status(zone_name: str) -> dict:
    """
    Get DNS status from DNSZone CR.

    Args:
        zone_name: The zone name

    Returns:
        Dict with DNS status:
        - phase: Ready/Syncing/Failed
        - zoneId: Cloudflare zone ID
        - records: List of status records with sync state
        - recordCount: Number of synced records
        - lastSyncedAt: Last sync timestamp
    """
    dnszone = get_dnszone(zone_name)
    return dnszone.status._raw
