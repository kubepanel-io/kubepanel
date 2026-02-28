"""
GlobalL3Firewall CR Operations

CRUD operations for GlobalL3Firewall custom resources in Kubernetes.
GlobalL3Firewall CRs manage Calico GlobalNetworkPolicy for network-level firewall rules.
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

# GlobalL3Firewall CRD constants
L3FIREWALL_GROUP = "kubepanel.io"
L3FIREWALL_VERSION = "v1alpha1"
L3FIREWALL_PLURAL = "globall3firewalls"

# Default CR name (singleton pattern)
DEFAULT_L3FIREWALL_NAME = "default"


class L3FirewallStatus:
    """
    Parsed GlobalL3Firewall CR status.

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


class GlobalL3Firewall:
    """
    GlobalL3Firewall CR wrapper.

    Represents a GlobalL3Firewall custom resource with easy access to spec and status.
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
    def status(self) -> L3FirewallStatus:
        """Parsed status."""
        return L3FirewallStatus(self._raw.get("status"))

    @property
    def enabled(self) -> bool:
        """Whether L3 firewall is enabled."""
        return self._raw.get("spec", {}).get("enabled", True)

    @property
    def rules(self) -> list[dict]:
        """L3 firewall rules from spec."""
        return self._raw.get("spec", {}).get("rules", [])

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

def get_l3_firewall(name: str = DEFAULT_L3FIREWALL_NAME) -> GlobalL3Firewall:
    """
    Get a GlobalL3Firewall CR by name.

    Args:
        name: The CR name (default: 'default')

    Returns:
        GlobalL3Firewall object

    Raises:
        K8sNotFoundError: If CR not found
        K8sClientError: For other K8s errors
    """
    custom_api = get_custom_api()

    try:
        result = custom_api.get_cluster_custom_object(
            group=L3FIREWALL_GROUP,
            version=L3FIREWALL_VERSION,
            plural=L3FIREWALL_PLURAL,
            name=name,
        )
        return GlobalL3Firewall(result)
    except ApiException as e:
        handle_api_exception(e, f"GlobalL3Firewall '{name}'")


def l3_firewall_exists(name: str = DEFAULT_L3FIREWALL_NAME) -> bool:
    """
    Check if a GlobalL3Firewall exists.

    Args:
        name: The CR name to check

    Returns:
        True if exists, False otherwise
    """
    try:
        get_l3_firewall(name)
        return True
    except K8sNotFoundError:
        return False


def create_l3_firewall(
    name: str = DEFAULT_L3FIREWALL_NAME,
    enabled: bool = True,
    rules: Optional[list] = None,
    labels: Optional[dict] = None,
) -> GlobalL3Firewall:
    """
    Create a new GlobalL3Firewall CR.

    Args:
        name: CR name (default: 'default')
        enabled: Whether L3 firewall is enabled
        rules: List of L3 firewall rules
        labels: Additional labels

    Returns:
        Created GlobalL3Firewall object

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

    # Build CR
    l3_firewall_cr = {
        "apiVersion": f"{L3FIREWALL_GROUP}/{L3FIREWALL_VERSION}",
        "kind": "GlobalL3Firewall",
        "metadata": {
            "name": name,
            "labels": all_labels,
        },
        "spec": spec,
    }

    logger.info(f"Creating GlobalL3Firewall CR '{name}'")

    try:
        result = custom_api.create_cluster_custom_object(
            group=L3FIREWALL_GROUP,
            version=L3FIREWALL_VERSION,
            plural=L3FIREWALL_PLURAL,
            body=l3_firewall_cr,
        )
        logger.info(f"Created GlobalL3Firewall CR '{name}'")
        return GlobalL3Firewall(result)
    except ApiException as e:
        handle_api_exception(e, f"GlobalL3Firewall '{name}'")


def delete_l3_firewall(name: str = DEFAULT_L3FIREWALL_NAME) -> None:
    """
    Delete a GlobalL3Firewall CR.

    The operator will delete the Calico GlobalNetworkPolicy.

    Args:
        name: The CR name to delete

    Raises:
        K8sNotFoundError: If CR not found
        K8sClientError: For other K8s errors
    """
    custom_api = get_custom_api()

    logger.info(f"Deleting GlobalL3Firewall CR '{name}'")

    try:
        custom_api.delete_cluster_custom_object(
            group=L3FIREWALL_GROUP,
            version=L3FIREWALL_VERSION,
            plural=L3FIREWALL_PLURAL,
            name=name,
        )
        logger.info(f"Deleted GlobalL3Firewall CR '{name}'")
    except ApiException as e:
        handle_api_exception(e, f"GlobalL3Firewall '{name}'")


def patch_l3_firewall(
    name: str = DEFAULT_L3FIREWALL_NAME,
    enabled: Optional[bool] = None,
    rules: Optional[list] = None,
) -> GlobalL3Firewall:
    """
    Patch GlobalL3Firewall CR spec.

    Args:
        name: The CR name
        enabled: Whether L3 firewall is enabled (None = don't change)
        rules: Complete list of rules (None = don't change)

    Returns:
        Updated GlobalL3Firewall object

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

    if not patch_body["spec"]:
        # Nothing to patch
        return get_l3_firewall(name)

    logger.info(f"Patching GlobalL3Firewall CR '{name}'")

    try:
        result = custom_api.patch_cluster_custom_object(
            group=L3FIREWALL_GROUP,
            version=L3FIREWALL_VERSION,
            plural=L3FIREWALL_PLURAL,
            name=name,
            body=patch_body,
        )
        logger.info(f"Patched GlobalL3Firewall CR '{name}'")
        return GlobalL3Firewall(result)
    except ApiException as e:
        handle_api_exception(e, f"GlobalL3Firewall '{name}'")


def set_l3_firewall_enabled(name: str = DEFAULT_L3FIREWALL_NAME, enabled: bool = True) -> GlobalL3Firewall:
    """
    Enable or disable the L3 firewall.

    Args:
        name: The CR name
        enabled: True to enable, False to disable

    Returns:
        Updated GlobalL3Firewall object
    """
    return patch_l3_firewall(name=name, enabled=enabled)


def get_or_create_l3_firewall(name: str = DEFAULT_L3FIREWALL_NAME) -> GlobalL3Firewall:
    """
    Get existing GlobalL3Firewall CR or create a new one with default settings.

    Args:
        name: The CR name

    Returns:
        GlobalL3Firewall object
    """
    try:
        return get_l3_firewall(name)
    except K8sNotFoundError:
        return create_l3_firewall(name=name, enabled=True, rules=[])


# =============================================================================
# Rule Management
# =============================================================================

def add_l3_rule(
    rule: dict,
    name: str = DEFAULT_L3FIREWALL_NAME,
) -> GlobalL3Firewall:
    """
    Add a rule to GlobalL3Firewall CR.

    Args:
        rule: Rule dict with name, action, source, destination, protocol
        name: The CR name

    Returns:
        Updated GlobalL3Firewall object
    """
    firewall = get_l3_firewall(name)
    rules = list(firewall.rules)
    rules.append(rule)
    return patch_l3_firewall(name=name, rules=rules)


def update_l3_rule(
    rule_index: int,
    rule: dict,
    name: str = DEFAULT_L3FIREWALL_NAME,
) -> GlobalL3Firewall:
    """
    Update a rule in GlobalL3Firewall CR.

    Args:
        rule_index: Index of the rule in spec.rules
        rule: Updated rule dict
        name: The CR name

    Returns:
        Updated GlobalL3Firewall object

    Raises:
        K8sClientError: If index out of range
    """
    firewall = get_l3_firewall(name)
    rules = list(firewall.rules)

    if 0 <= rule_index < len(rules):
        rules[rule_index] = rule
    else:
        raise K8sClientError(f"Rule index {rule_index} out of range")

    return patch_l3_firewall(name=name, rules=rules)


def delete_l3_rule(
    rule_index: int,
    name: str = DEFAULT_L3FIREWALL_NAME,
) -> GlobalL3Firewall:
    """
    Delete a rule from GlobalL3Firewall CR.

    Args:
        rule_index: Index of the rule to delete
        name: The CR name

    Returns:
        Updated GlobalL3Firewall object

    Raises:
        K8sClientError: If index out of range
    """
    firewall = get_l3_firewall(name)
    rules = list(firewall.rules)

    if 0 <= rule_index < len(rules):
        deleted = rules.pop(rule_index)
        logger.info(f"Removing rule at index {rule_index}: {deleted}")
    else:
        raise K8sClientError(f"Rule index {rule_index} out of range")

    return patch_l3_firewall(name=name, rules=rules)


def get_l3_rule(
    rule_index: int,
    name: str = DEFAULT_L3FIREWALL_NAME,
) -> Optional[dict]:
    """
    Get a single L3 rule by index.

    Args:
        rule_index: Index of the rule
        name: The CR name

    Returns:
        Rule dict or None if index out of range
    """
    firewall = get_l3_firewall(name)
    rules = firewall.rules
    if 0 <= rule_index < len(rules):
        return rules[rule_index]
    return None


def get_l3_rules(name: str = DEFAULT_L3FIREWALL_NAME) -> list[dict]:
    """
    Get all rules from GlobalL3Firewall CR.

    Args:
        name: The CR name

    Returns:
        List of rule dicts
    """
    firewall = get_l3_firewall(name)
    return firewall.rules
