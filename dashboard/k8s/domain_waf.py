"""
DomainWAF CR Operations

CRUD operations for DomainWAF custom resources in Kubernetes.
DomainWAF CRs manage ModSecurity WAF rules on per-domain nginx.
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

# DomainWAF CRD constants
DOMAINWAF_GROUP = "kubepanel.io"
DOMAINWAF_VERSION = "v1alpha1"
DOMAINWAF_PLURAL = "domainwafs"

# Default CR name (one per domain namespace)
DEFAULT_DOMAINWAF_NAME = "default"


class DomainWAFStatus:
    """
    Parsed DomainWAF CR status.

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


class DomainWAF:
    """
    DomainWAF CR wrapper.

    Represents a DomainWAF custom resource with easy access to spec and status.
    """

    def __init__(self, cr_dict: dict):
        self._raw = cr_dict

    @property
    def name(self) -> str:
        """CR metadata name."""
        return self._raw.get("metadata", {}).get("name", "")

    @property
    def namespace(self) -> str:
        """CR metadata namespace."""
        return self._raw.get("metadata", {}).get("namespace", "")

    @property
    def spec(self) -> dict:
        """Raw spec dict."""
        return self._raw.get("spec", {})

    @property
    def status(self) -> DomainWAFStatus:
        """Parsed status."""
        return DomainWAFStatus(self._raw.get("status"))

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
    def protected_paths(self) -> list[dict]:
        """Protected paths from spec."""
        return self._raw.get("spec", {}).get("protectedPaths", [])

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

def get_domainwaf(namespace: str, name: str = DEFAULT_DOMAINWAF_NAME) -> DomainWAF:
    """
    Get a DomainWAF CR by namespace and name.

    Args:
        namespace: The domain namespace (e.g., 'dom-example-com')
        name: The CR name (default: 'default')

    Returns:
        DomainWAF object

    Raises:
        K8sNotFoundError: If CR not found
        K8sClientError: For other K8s errors
    """
    custom_api = get_custom_api()

    try:
        result = custom_api.get_namespaced_custom_object(
            group=DOMAINWAF_GROUP,
            version=DOMAINWAF_VERSION,
            plural=DOMAINWAF_PLURAL,
            namespace=namespace,
            name=name,
        )
        return DomainWAF(result)
    except ApiException as e:
        handle_api_exception(e, f"DomainWAF '{namespace}/{name}'")


def domainwaf_exists(namespace: str, name: str = DEFAULT_DOMAINWAF_NAME) -> bool:
    """
    Check if a DomainWAF exists.

    Args:
        namespace: The domain namespace
        name: The CR name to check

    Returns:
        True if exists, False otherwise
    """
    try:
        get_domainwaf(namespace, name)
        return True
    except K8sNotFoundError:
        return False


def create_domainwaf(
    namespace: str,
    name: str = DEFAULT_DOMAINWAF_NAME,
    enabled: bool = True,
    rules: Optional[list] = None,
    geo_block: Optional[dict] = None,
    labels: Optional[dict] = None,
) -> DomainWAF:
    """
    Create a new DomainWAF CR.

    Args:
        namespace: The domain namespace
        name: CR name (default: 'default')
        enabled: Whether WAF is enabled
        rules: List of WAF rules
        geo_block: Geo-blocking configuration
        labels: Additional labels

    Returns:
        Created DomainWAF object

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
    domainwaf_cr = {
        "apiVersion": f"{DOMAINWAF_GROUP}/{DOMAINWAF_VERSION}",
        "kind": "DomainWAF",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": all_labels,
        },
        "spec": spec,
    }

    logger.info(f"Creating DomainWAF CR '{namespace}/{name}'")

    try:
        result = custom_api.create_namespaced_custom_object(
            group=DOMAINWAF_GROUP,
            version=DOMAINWAF_VERSION,
            plural=DOMAINWAF_PLURAL,
            namespace=namespace,
            body=domainwaf_cr,
        )
        logger.info(f"Created DomainWAF CR '{namespace}/{name}'")
        return DomainWAF(result)
    except ApiException as e:
        handle_api_exception(e, f"DomainWAF '{namespace}/{name}'")


def delete_domainwaf(namespace: str, name: str = DEFAULT_DOMAINWAF_NAME) -> None:
    """
    Delete a DomainWAF CR.

    The operator will clear ModSecurity rules from domain nginx.

    Args:
        namespace: The domain namespace
        name: The CR name to delete

    Raises:
        K8sNotFoundError: If CR not found
        K8sClientError: For other K8s errors
    """
    custom_api = get_custom_api()

    logger.info(f"Deleting DomainWAF CR '{namespace}/{name}'")

    try:
        custom_api.delete_namespaced_custom_object(
            group=DOMAINWAF_GROUP,
            version=DOMAINWAF_VERSION,
            plural=DOMAINWAF_PLURAL,
            namespace=namespace,
            name=name,
        )
        logger.info(f"Deleted DomainWAF CR '{namespace}/{name}'")
    except ApiException as e:
        handle_api_exception(e, f"DomainWAF '{namespace}/{name}'")


def patch_domainwaf(
    namespace: str,
    name: str = DEFAULT_DOMAINWAF_NAME,
    enabled: Optional[bool] = None,
    rules: Optional[list] = None,
    geo_block: Optional[dict] = None,
    protected_paths: Optional[list] = None,
) -> DomainWAF:
    """
    Patch DomainWAF CR spec.

    Args:
        namespace: The domain namespace
        name: The CR name
        enabled: Whether WAF is enabled (None = don't change)
        rules: Complete list of WAF rules (None = don't change)
        geo_block: Geo-blocking config (None = don't change)
        protected_paths: Complete list of protected paths (None = don't change)

    Returns:
        Updated DomainWAF object

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
    if protected_paths is not None:
        patch_body["spec"]["protectedPaths"] = protected_paths

    if not patch_body["spec"]:
        # Nothing to patch
        return get_domainwaf(namespace, name)

    logger.info(f"Patching DomainWAF CR '{namespace}/{name}'")

    try:
        result = custom_api.patch_namespaced_custom_object(
            group=DOMAINWAF_GROUP,
            version=DOMAINWAF_VERSION,
            plural=DOMAINWAF_PLURAL,
            namespace=namespace,
            name=name,
            body=patch_body,
        )
        logger.info(f"Patched DomainWAF CR '{namespace}/{name}'")
        return DomainWAF(result)
    except ApiException as e:
        handle_api_exception(e, f"DomainWAF '{namespace}/{name}'")


def set_domainwaf_enabled(
    namespace: str,
    name: str = DEFAULT_DOMAINWAF_NAME,
    enabled: bool = True,
) -> DomainWAF:
    """
    Enable or disable the DomainWAF.

    Args:
        namespace: The domain namespace
        name: The CR name
        enabled: True to enable, False to disable

    Returns:
        Updated DomainWAF object
    """
    return patch_domainwaf(namespace=namespace, name=name, enabled=enabled)


def get_or_create_domainwaf(
    namespace: str,
    name: str = DEFAULT_DOMAINWAF_NAME,
) -> DomainWAF:
    """
    Get existing DomainWAF CR or create a new one with default settings.

    Args:
        namespace: The domain namespace
        name: The CR name

    Returns:
        DomainWAF object
    """
    try:
        return get_domainwaf(namespace, name)
    except K8sNotFoundError:
        return create_domainwaf(namespace=namespace, name=name, enabled=True, rules=[])


# =============================================================================
# Rule Management
# =============================================================================

def add_domain_waf_rule(
    namespace: str,
    rule: dict,
    name: str = DEFAULT_DOMAINWAF_NAME,
) -> DomainWAF:
    """
    Add a WAF rule to DomainWAF CR.

    Args:
        namespace: The domain namespace
        rule: Rule dict with ip, path, pathMatchType, userAgent, action, comment
        name: The CR name

    Returns:
        Updated DomainWAF object
    """
    domainwaf = get_domainwaf(namespace, name)
    rules = list(domainwaf.rules)
    rules.append(rule)
    return patch_domainwaf(namespace=namespace, name=name, rules=rules)


def update_domain_waf_rule(
    namespace: str,
    rule_index: int,
    rule: dict,
    name: str = DEFAULT_DOMAINWAF_NAME,
) -> DomainWAF:
    """
    Update a WAF rule in DomainWAF CR.

    Args:
        namespace: The domain namespace
        rule_index: Index of the rule in spec.rules
        rule: Updated rule dict
        name: The CR name

    Returns:
        Updated DomainWAF object

    Raises:
        K8sClientError: If index out of range
    """
    domainwaf = get_domainwaf(namespace, name)
    rules = list(domainwaf.rules)

    if 0 <= rule_index < len(rules):
        rules[rule_index] = rule
    else:
        raise K8sClientError(f"Rule index {rule_index} out of range")

    return patch_domainwaf(namespace=namespace, name=name, rules=rules)


def delete_domain_waf_rule(
    namespace: str,
    rule_index: int,
    name: str = DEFAULT_DOMAINWAF_NAME,
) -> DomainWAF:
    """
    Delete a WAF rule from DomainWAF CR.

    Args:
        namespace: The domain namespace
        rule_index: Index of the rule to delete
        name: The CR name

    Returns:
        Updated DomainWAF object

    Raises:
        K8sClientError: If index out of range
    """
    domainwaf = get_domainwaf(namespace, name)
    rules = list(domainwaf.rules)

    if 0 <= rule_index < len(rules):
        deleted = rules.pop(rule_index)
        logger.info(f"Removing rule at index {rule_index}: {deleted}")
    else:
        raise K8sClientError(f"Rule index {rule_index} out of range")

    return patch_domainwaf(namespace=namespace, name=name, rules=rules)


def get_domain_waf_rule(
    namespace: str,
    rule_index: int,
    name: str = DEFAULT_DOMAINWAF_NAME,
) -> Optional[dict]:
    """
    Get a single WAF rule by index.

    Args:
        namespace: The domain namespace
        rule_index: Index of the rule
        name: The CR name

    Returns:
        Rule dict or None if index out of range
    """
    domainwaf = get_domainwaf(namespace, name)
    rules = domainwaf.rules
    if 0 <= rule_index < len(rules):
        return rules[rule_index]
    return None


def get_domain_waf_rules(
    namespace: str,
    name: str = DEFAULT_DOMAINWAF_NAME,
) -> list[dict]:
    """
    Get all WAF rules from DomainWAF CR.

    Args:
        namespace: The domain namespace
        name: The CR name

    Returns:
        List of rule dicts
    """
    domainwaf = get_domainwaf(namespace, name)
    return domainwaf.rules


# =============================================================================
# Geo-blocking Management
# =============================================================================

def set_geo_blocking_enabled(
    namespace: str,
    enabled: bool,
    name: str = DEFAULT_DOMAINWAF_NAME,
) -> DomainWAF:
    """
    Enable or disable geo-blocking for a domain.

    Args:
        namespace: The domain namespace
        enabled: True to enable, False to disable
        name: The CR name

    Returns:
        Updated DomainWAF object
    """
    domainwaf = get_domainwaf(namespace, name)
    geo_block = domainwaf.geo_block or {}
    geo_block["enabled"] = enabled
    return patch_domainwaf(namespace=namespace, name=name, geo_block=geo_block)


def add_blocked_country(
    namespace: str,
    country_code: str,
    name: str = DEFAULT_DOMAINWAF_NAME,
) -> DomainWAF:
    """
    Add a country to the blocked list.

    Args:
        namespace: The domain namespace
        country_code: ISO 3166-1 alpha-2 country code (e.g., 'CN', 'RU')
        name: The CR name

    Returns:
        Updated DomainWAF object
    """
    domainwaf = get_domainwaf(namespace, name)
    geo_block = domainwaf.geo_block or {"enabled": False, "blockedCountries": []}
    countries = geo_block.get("blockedCountries", [])

    # Add if not already present
    country_code = country_code.upper()
    if country_code not in countries:
        countries.append(country_code)
        geo_block["blockedCountries"] = countries

    return patch_domainwaf(namespace=namespace, name=name, geo_block=geo_block)


def remove_blocked_country(
    namespace: str,
    country_code: str,
    name: str = DEFAULT_DOMAINWAF_NAME,
) -> DomainWAF:
    """
    Remove a country from the blocked list.

    Args:
        namespace: The domain namespace
        country_code: ISO 3166-1 alpha-2 country code
        name: The CR name

    Returns:
        Updated DomainWAF object
    """
    domainwaf = get_domainwaf(namespace, name)
    geo_block = domainwaf.geo_block or {"enabled": False, "blockedCountries": []}
    countries = geo_block.get("blockedCountries", [])

    # Remove if present
    country_code = country_code.upper()
    if country_code in countries:
        countries.remove(country_code)
        geo_block["blockedCountries"] = countries

    return patch_domainwaf(namespace=namespace, name=name, geo_block=geo_block)


# =============================================================================
# Protected Paths Management
# =============================================================================

def get_domain_protected_paths(
    namespace: str,
    name: str = DEFAULT_DOMAINWAF_NAME,
) -> list[dict]:
    """
    Get all protected paths from DomainWAF CR.

    Args:
        namespace: The domain namespace
        name: The CR name

    Returns:
        List of protected path dicts
    """
    domainwaf = get_domainwaf(namespace, name)
    return domainwaf.protected_paths


def get_domain_protected_path(
    namespace: str,
    path_index: int,
    name: str = DEFAULT_DOMAINWAF_NAME,
) -> Optional[dict]:
    """
    Get a single protected path by index.

    Args:
        namespace: The domain namespace
        path_index: Index of the protected path
        name: The CR name

    Returns:
        Protected path dict or None if index out of range
    """
    domainwaf = get_domainwaf(namespace, name)
    paths = domainwaf.protected_paths
    if 0 <= path_index < len(paths):
        return paths[path_index]
    return None


def add_domain_protected_path(
    namespace: str,
    protected_path: dict,
    name: str = DEFAULT_DOMAINWAF_NAME,
) -> DomainWAF:
    """
    Add a protected path to DomainWAF CR.

    Args:
        namespace: The domain namespace
        protected_path: Protected path dict with path, pathMatchType, allowedIp, allowedCountries, comment
        name: The CR name

    Returns:
        Updated DomainWAF object
    """
    domainwaf = get_domainwaf(namespace, name)
    paths = list(domainwaf.protected_paths)
    paths.append(protected_path)
    return patch_domainwaf(namespace=namespace, name=name, protected_paths=paths)


def update_domain_protected_path(
    namespace: str,
    path_index: int,
    protected_path: dict,
    name: str = DEFAULT_DOMAINWAF_NAME,
) -> DomainWAF:
    """
    Update a protected path in DomainWAF CR.

    Args:
        namespace: The domain namespace
        path_index: Index of the protected path in spec.protectedPaths
        protected_path: Updated protected path dict
        name: The CR name

    Returns:
        Updated DomainWAF object

    Raises:
        K8sClientError: If index out of range
    """
    domainwaf = get_domainwaf(namespace, name)
    paths = list(domainwaf.protected_paths)

    if 0 <= path_index < len(paths):
        paths[path_index] = protected_path
    else:
        raise K8sClientError(f"Protected path index {path_index} out of range")

    return patch_domainwaf(namespace=namespace, name=name, protected_paths=paths)


def delete_domain_protected_path(
    namespace: str,
    path_index: int,
    name: str = DEFAULT_DOMAINWAF_NAME,
) -> DomainWAF:
    """
    Delete a protected path from DomainWAF CR.

    Args:
        namespace: The domain namespace
        path_index: Index of the protected path to delete
        name: The CR name

    Returns:
        Updated DomainWAF object

    Raises:
        K8sClientError: If index out of range
    """
    domainwaf = get_domainwaf(namespace, name)
    paths = list(domainwaf.protected_paths)

    if 0 <= path_index < len(paths):
        deleted = paths.pop(path_index)
        logger.info(f"Removing protected path at index {path_index}: {deleted}")
    else:
        raise K8sClientError(f"Protected path index {path_index} out of range")

    return patch_domainwaf(namespace=namespace, name=name, protected_paths=paths)
