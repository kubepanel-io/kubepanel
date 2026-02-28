"""
GlobalWAF CR Operations

CRUD operations for GlobalWAF custom resources in Kubernetes.
GlobalWAF CRs manage ModSecurity WAF rules on ingress-nginx.
"""

from kubernetes.client.rest import ApiException
from typing import Optional
import logging

from .client import (
    get_custom_api,
    handle_api_exception,
    K8sNotFoundError,
    K8sClientError,
)

logger = logging.getLogger(__name__)

# GlobalWAF CRD constants
GLOBALWAF_GROUP = "kubepanel.io"
GLOBALWAF_VERSION = "v1alpha1"
GLOBALWAF_PLURAL = "globalwafs"

# Default CR name (singleton pattern)
DEFAULT_GLOBALWAF_NAME = "default"


class GlobalWAFStatus:
    """
    Parsed GlobalWAF CR status.

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
    def rule_count(self) -> int:
        return self._raw.get("ruleCount", 0)

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
    def is_disabled(self) -> bool:
        return self.phase == "Disabled"

    @property
    def last_synced_at(self) -> Optional[str]:
        return self._raw.get("lastSyncedAt")


class GlobalWAF:
    """
    GlobalWAF CR wrapper.

    Represents a GlobalWAF custom resource with easy access to spec and status.
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
    def status(self) -> GlobalWAFStatus:
        """Parsed status."""
        return GlobalWAFStatus(self._raw.get("status"))

    @property
    def enabled(self) -> bool:
        """Whether WAF is enabled."""
        return self._raw.get("spec", {}).get("enabled", True)

    @property
    def rules(self) -> list[dict]:
        """WAF rules from spec."""
        return self._raw.get("spec", {}).get("rules", [])

    @property
    def geo_block(self) -> Optional[dict]:
        """Geo-blocking configuration."""
        return self._raw.get("spec", {}).get("geoBlock")

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

def get_globalwaf(name: str = DEFAULT_GLOBALWAF_NAME) -> GlobalWAF:
    """
    Get a GlobalWAF CR by name.

    Args:
        name: The CR name (default: 'default')

    Returns:
        GlobalWAF object

    Raises:
        K8sNotFoundError: If CR not found
        K8sClientError: For other K8s errors
    """
    custom_api = get_custom_api()

    try:
        result = custom_api.get_cluster_custom_object(
            group=GLOBALWAF_GROUP,
            version=GLOBALWAF_VERSION,
            plural=GLOBALWAF_PLURAL,
            name=name,
        )
        return GlobalWAF(result)
    except ApiException as e:
        handle_api_exception(e, f"GlobalWAF '{name}'")


def globalwaf_exists(name: str = DEFAULT_GLOBALWAF_NAME) -> bool:
    """
    Check if a GlobalWAF exists.

    Args:
        name: The CR name to check

    Returns:
        True if exists, False otherwise
    """
    try:
        get_globalwaf(name)
        return True
    except K8sNotFoundError:
        return False


def create_globalwaf(
    name: str = DEFAULT_GLOBALWAF_NAME,
    enabled: bool = True,
    rules: Optional[list] = None,
    geo_block: Optional[dict] = None,
    labels: Optional[dict] = None,
) -> GlobalWAF:
    """
    Create a new GlobalWAF CR.

    Args:
        name: CR name (default: 'default')
        enabled: Whether WAF is enabled
        rules: List of WAF rules
        geo_block: Geo-blocking configuration
        labels: Additional labels

    Returns:
        Created GlobalWAF object

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
    spec = {
        "enabled": enabled,
    }
    if rules:
        spec["rules"] = rules
    if geo_block:
        spec["geoBlock"] = geo_block

    # Build CR
    globalwaf_cr = {
        "apiVersion": f"{GLOBALWAF_GROUP}/{GLOBALWAF_VERSION}",
        "kind": "GlobalWAF",
        "metadata": {
            "name": name,
            "labels": all_labels,
        },
        "spec": spec,
    }

    logger.info(f"Creating GlobalWAF CR '{name}'")

    try:
        result = custom_api.create_cluster_custom_object(
            group=GLOBALWAF_GROUP,
            version=GLOBALWAF_VERSION,
            plural=GLOBALWAF_PLURAL,
            body=globalwaf_cr,
        )
        logger.info(f"Created GlobalWAF CR '{name}'")
        return GlobalWAF(result)
    except ApiException as e:
        handle_api_exception(e, f"GlobalWAF '{name}'")


def delete_globalwaf(name: str = DEFAULT_GLOBALWAF_NAME) -> None:
    """
    Delete a GlobalWAF CR.

    The operator will clear ModSecurity rules from ingress-nginx.

    Args:
        name: The CR name to delete

    Raises:
        K8sNotFoundError: If CR not found
        K8sClientError: For other K8s errors
    """
    custom_api = get_custom_api()

    logger.info(f"Deleting GlobalWAF CR '{name}'")

    try:
        custom_api.delete_cluster_custom_object(
            group=GLOBALWAF_GROUP,
            version=GLOBALWAF_VERSION,
            plural=GLOBALWAF_PLURAL,
            name=name,
        )
        logger.info(f"Deleted GlobalWAF CR '{name}'")
    except ApiException as e:
        handle_api_exception(e, f"GlobalWAF '{name}'")


def patch_globalwaf(
    name: str = DEFAULT_GLOBALWAF_NAME,
    enabled: Optional[bool] = None,
    rules: Optional[list] = None,
    geo_block: Optional[dict] = None,
) -> GlobalWAF:
    """
    Patch GlobalWAF CR spec.

    Args:
        name: The CR name
        enabled: Whether WAF is enabled (None = don't change)
        rules: Complete list of WAF rules (None = don't change)
        geo_block: Geo-blocking config (None = don't change)

    Returns:
        Updated GlobalWAF object

    Raises:
        K8sNotFoundError: If CR not found
        K8sClientError: For other K8s errors
    """
    custom_api = get_custom_api()

    patch_body = {"spec": {}}

    if enabled is not None:
        patch_body["spec"]["enabled"] = enabled
    if rules is not None:
        patch_body["spec"]["rules"] = rules
    if geo_block is not None:
        patch_body["spec"]["geoBlock"] = geo_block

    if not patch_body["spec"]:
        # Nothing to patch
        return get_globalwaf(name)

    logger.info(f"Patching GlobalWAF CR '{name}'")

    try:
        result = custom_api.patch_cluster_custom_object(
            group=GLOBALWAF_GROUP,
            version=GLOBALWAF_VERSION,
            plural=GLOBALWAF_PLURAL,
            name=name,
            body=patch_body,
        )
        logger.info(f"Patched GlobalWAF CR '{name}'")
        return GlobalWAF(result)
    except ApiException as e:
        handle_api_exception(e, f"GlobalWAF '{name}'")


def set_globalwaf_enabled(name: str = DEFAULT_GLOBALWAF_NAME, enabled: bool = True) -> GlobalWAF:
    """
    Enable or disable the GlobalWAF.

    Args:
        name: The CR name
        enabled: True to enable, False to disable

    Returns:
        Updated GlobalWAF object
    """
    return patch_globalwaf(name=name, enabled=enabled)


def get_or_create_globalwaf(name: str = DEFAULT_GLOBALWAF_NAME) -> GlobalWAF:
    """
    Get existing GlobalWAF CR or create a new one with default settings.

    Args:
        name: The CR name

    Returns:
        GlobalWAF object
    """
    try:
        return get_globalwaf(name)
    except K8sNotFoundError:
        return create_globalwaf(name=name, enabled=True, rules=[])


# =============================================================================
# Rule Management
# =============================================================================

def add_waf_rule(
    rule: dict,
    name: str = DEFAULT_GLOBALWAF_NAME,
) -> GlobalWAF:
    """
    Add a WAF rule to GlobalWAF CR.

    Args:
        rule: Rule dict with domain, ip, path, pathMatchType, action, comment
        name: The CR name

    Returns:
        Updated GlobalWAF object
    """
    globalwaf = get_globalwaf(name)
    rules = list(globalwaf.rules)
    rules.append(rule)
    return patch_globalwaf(name=name, rules=rules)


def update_waf_rule(
    rule_index: int,
    rule: dict,
    name: str = DEFAULT_GLOBALWAF_NAME,
) -> GlobalWAF:
    """
    Update a WAF rule in GlobalWAF CR.

    Args:
        rule_index: Index of the rule in spec.rules
        rule: Updated rule dict
        name: The CR name

    Returns:
        Updated GlobalWAF object

    Raises:
        K8sClientError: If index out of range
    """
    globalwaf = get_globalwaf(name)
    rules = list(globalwaf.rules)

    if 0 <= rule_index < len(rules):
        rules[rule_index] = rule
    else:
        raise K8sClientError(f"Rule index {rule_index} out of range")

    return patch_globalwaf(name=name, rules=rules)


def delete_waf_rule(
    rule_index: int,
    name: str = DEFAULT_GLOBALWAF_NAME,
) -> GlobalWAF:
    """
    Delete a WAF rule from GlobalWAF CR.

    Args:
        rule_index: Index of the rule to delete
        name: The CR name

    Returns:
        Updated GlobalWAF object

    Raises:
        K8sClientError: If index out of range
    """
    globalwaf = get_globalwaf(name)
    rules = list(globalwaf.rules)

    if 0 <= rule_index < len(rules):
        deleted = rules.pop(rule_index)
        logger.info(f"Removing rule at index {rule_index}: {deleted}")
    else:
        raise K8sClientError(f"Rule index {rule_index} out of range")

    return patch_globalwaf(name=name, rules=rules)


def get_waf_rule(
    rule_index: int,
    name: str = DEFAULT_GLOBALWAF_NAME,
) -> Optional[dict]:
    """
    Get a single WAF rule by index.

    Args:
        rule_index: Index of the rule
        name: The CR name

    Returns:
        Rule dict or None if index out of range
    """
    globalwaf = get_globalwaf(name)
    rules = globalwaf.rules
    if 0 <= rule_index < len(rules):
        return rules[rule_index]
    return None


def get_waf_rules(name: str = DEFAULT_GLOBALWAF_NAME) -> list[dict]:
    """
    Get all WAF rules from GlobalWAF CR.

    Args:
        name: The CR name

    Returns:
        List of rule dicts
    """
    globalwaf = get_globalwaf(name)
    return globalwaf.rules
