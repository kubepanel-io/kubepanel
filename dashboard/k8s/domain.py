"""
Domain CR Operations

CRUD operations for Domain custom resources in Kubernetes.
This is the main integration point between Django and the KubePanel operator.
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

# Domain CRD constants
DOMAIN_GROUP = "kubepanel.io"
DOMAIN_VERSION = "v1alpha1"
DOMAIN_PLURAL = "domains"


def _sanitize_cr_name(domain_name: str) -> str:
    """
    Convert domain name to a valid CR name.
    
    e.g., 'example.com' -> 'example-com'
    e.g., 'my.sub.domain.com' -> 'my-sub-domain-com'
    """
    sanitized = re.sub(r'[^a-z0-9-]', '-', domain_name.lower())
    sanitized = re.sub(r'-+', '-', sanitized)  # collapse multiple dashes
    return sanitized.strip('-')


class DomainSpec:
    """
    Domain specification builder.

    Provides a clean interface to build Domain CR specs with validation.
    Now supports multiple workload types (PHP, Python, Node.js, etc.)
    """

    def __init__(
        self,
        domain_name: str,
        # Workload configuration (replaces php_version)
        workload_type: str,
        workload_version: str,
        workload_image: str,
        workload_port: int = 9000,
        proxy_mode: str = 'fastcgi',
        # Resource limits
        storage: str = '5Gi',
        cpu_limit: str = '500m',
        memory_limit: str = '256Mi',
    ):
        """
        Initialize required fields.

        Args:
            domain_name: Primary domain name (e.g., 'example.com')
            workload_type: Workload type slug (e.g., 'php', 'python', 'nodejs')
            workload_version: Version string (e.g., '8.2', '3.11', '20')
            workload_image: Full container image URL
            workload_port: App container port (e.g., 9001 for PHP, 8000 for Python)
            proxy_mode: How nginx proxies to app ('fastcgi', 'http', 'uwsgi')
            storage: Storage size (e.g., '5Gi')
            cpu_limit: CPU limit (e.g., '500m')
            memory_limit: Memory limit (e.g., '256Mi')
        """
        self.domain_name = domain_name
        self.workload_type = workload_type
        self.workload_version = workload_version
        self.workload_image = workload_image
        self.workload_port = workload_port
        self.proxy_mode = proxy_mode
        self.storage = storage
        self.cpu_limit = cpu_limit
        self.memory_limit = memory_limit

        # Optional fields with defaults
        self.title: Optional[str] = None
        self.aliases: list[str] = []
        self.suspended: bool = False

        # Workload optional fields
        self.workload_command: Optional[list] = None
        self.workload_args: Optional[list] = None
        self.workload_env: Optional[list] = None  # [{"name": "...", "value": "..."}]
        self.workload_settings: Optional[dict] = None  # Type-specific settings
        self.workload_custom_config: Optional[str] = None

        # Resource requests (optional, operator uses low defaults)
        self.cpu_request: Optional[str] = None
        self.memory_request: Optional[str] = None

        # Webserver settings (optional)
        self.document_root: Optional[str] = None
        self.client_max_body_size: Optional[str] = None
        self.ssl_redirect: Optional[bool] = None
        self.www_redirect: Optional[str] = None
        self.custom_nginx_config: Optional[str] = None

        # Feature toggles (optional)
        self.database_enabled: Optional[bool] = None
        self.email_enabled: Optional[bool] = None
        self.dkim_selector: Optional[str] = None
        self.dkim_secret_ref: Optional[dict] = None  # {"name": "...", "namespace": "..."}
        self.sftp_enabled: Optional[bool] = None
        self.wordpress_preinstall: Optional[bool] = None

        # DNS configuration (optional)
        self.dns_enabled: Optional[bool] = None
        self.dns_credential_secret_ref: Optional[dict] = None  # {"name": "...", "namespace": "..."}
        self.dns_zone_name: Optional[str] = None
        self.dns_zone_create: Optional[bool] = None
        self.dns_auto_create_records: Optional[bool] = None
        self.dns_records: Optional[list] = None  # List of record dicts

    def to_dict(self) -> dict:
        """Convert to Domain CR spec dict."""
        spec = {
            "domainName": self.domain_name,
            "workload": {
                "type": self.workload_type,
                "version": self.workload_version,
                "image": self.workload_image,
                "port": self.workload_port,
                "proxyMode": self.proxy_mode,
            },
            "resources": {
                "storage": self.storage,
                "limits": {
                    "cpu": self.cpu_limit,
                    "memory": self.memory_limit,
                },
            },
        }

        # Add optional workload fields
        if self.workload_command:
            spec["workload"]["command"] = self.workload_command
        if self.workload_args:
            spec["workload"]["args"] = self.workload_args
        if self.workload_env:
            spec["workload"]["env"] = self.workload_env
        if self.workload_settings:
            spec["workload"]["settings"] = self.workload_settings
        if self.workload_custom_config:
            spec["workload"]["customConfig"] = self.workload_custom_config

        # Add optional title
        if self.title:
            spec["title"] = self.title

        # Add aliases if any
        if self.aliases:
            spec["aliases"] = self.aliases

        # Add suspended if True
        if self.suspended:
            spec["suspended"] = True

        # Add resource requests if any are set
        if self.cpu_request or self.memory_request:
            spec["resources"]["requests"] = {}
            if self.cpu_request:
                spec["resources"]["requests"]["cpu"] = self.cpu_request
            if self.memory_request:
                spec["resources"]["requests"]["memory"] = self.memory_request
        
        # Add webserver settings if any are set
        webserver = {}
        if self.document_root:
            webserver["documentRoot"] = self.document_root
        if self.client_max_body_size:
            webserver["clientMaxBodySize"] = self.client_max_body_size
        if self.ssl_redirect is not None:
            webserver["sslRedirect"] = self.ssl_redirect
        if self.www_redirect:
            webserver["wwwRedirect"] = self.www_redirect
        if self.custom_nginx_config:
            webserver["customConfig"] = self.custom_nginx_config
        if webserver:
            spec["webserver"] = webserver
        
        # Add feature toggles if explicitly set
        if self.database_enabled is not None:
            spec["database"] = {"enabled": self.database_enabled}

        if self.email_enabled is not None or self.dkim_selector or self.dkim_secret_ref:
            spec["email"] = {}
            if self.email_enabled is not None:
                spec["email"]["enabled"] = self.email_enabled
            if self.dkim_selector:
                spec["email"]["dkimSelector"] = self.dkim_selector
            if self.dkim_secret_ref:
                spec["email"]["dkimSecretRef"] = self.dkim_secret_ref

        if self.sftp_enabled is not None:
            spec["sftp"] = {"enabled": self.sftp_enabled}

        if self.wordpress_preinstall is not None:
            spec["wordpress"] = {"preinstall": self.wordpress_preinstall}

        # Add DNS configuration if enabled
        if self.dns_enabled is not None:
            dns = {"enabled": self.dns_enabled}
            if self.dns_credential_secret_ref:
                dns["credentialSecretRef"] = self.dns_credential_secret_ref
            if self.dns_zone_name or self.dns_zone_create is not None:
                dns["zone"] = {}
                if self.dns_zone_name:
                    dns["zone"]["name"] = self.dns_zone_name
                if self.dns_zone_create is not None:
                    dns["zone"]["create"] = self.dns_zone_create
            if self.dns_auto_create_records is not None:
                dns["autoCreateRecords"] = self.dns_auto_create_records
            if self.dns_records:
                dns["records"] = self.dns_records
            spec["dns"] = dns

        return spec


class DomainStatus:
    """
    Parsed Domain CR status.
    
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
    def namespace(self) -> str:
        return self._raw.get("namespace", "")
    
    @property
    def is_ready(self) -> bool:
        return self.phase == "Ready"
    
    @property
    def is_failed(self) -> bool:
        return self.phase == "Failed"
    
    @property
    def conditions(self) -> list[dict]:
        return self._raw.get("conditions", [])
    
    def get_condition(self, condition_type: str) -> Optional[dict]:
        """Get a specific condition by type."""
        for cond in self.conditions:
            if cond.get("type") == condition_type:
                return cond
        return None
    
    # SFTP access
    @property
    def sftp_host(self) -> Optional[str]:
        return self._raw.get("sftp", {}).get("host")
    
    @property
    def sftp_port(self) -> Optional[int]:
        return self._raw.get("sftp", {}).get("port")
    
    @property
    def sftp_username(self) -> Optional[str]:
        return self._raw.get("sftp", {}).get("username")
    
    @property
    def sftp_password_secret_ref(self) -> Optional[dict]:
        return self._raw.get("sftp", {}).get("passwordSecretRef")
    
    # Database access
    @property
    def database_host(self) -> Optional[str]:
        return self._raw.get("database", {}).get("host")
    
    @property
    def database_name(self) -> Optional[str]:
        return self._raw.get("database", {}).get("name")
    
    @property
    def database_username(self) -> Optional[str]:
        return self._raw.get("database", {}).get("username")
    
    @property
    def database_password_secret_ref(self) -> Optional[dict]:
        return self._raw.get("database", {}).get("passwordSecretRef")
    
    # Email/DKIM
    @property
    def dkim_public_key(self) -> Optional[str]:
        return self._raw.get("email", {}).get("dkimPublicKey")

    @property
    def dkim_dns_record(self) -> Optional[str]:
        return self._raw.get("email", {}).get("dkimDnsRecord")

    # DNS
    @property
    def dns_phase(self) -> Optional[str]:
        return self._raw.get("dns", {}).get("phase")

    @property
    def dns_zone_id(self) -> Optional[str]:
        return self._raw.get("dns", {}).get("zone", {}).get("id")

    @property
    def dns_zone_name(self) -> Optional[str]:
        return self._raw.get("dns", {}).get("zone", {}).get("name")

    @property
    def dns_records(self) -> list[dict]:
        return self._raw.get("dns", {}).get("records", [])

    @property
    def dns_message(self) -> Optional[str]:
        return self._raw.get("dns", {}).get("message")


class Domain:
    """
    Domain CR wrapper.
    
    Represents a Domain custom resource with easy access to spec and status.
    """
    
    def __init__(self, cr_dict: dict):
        self._raw = cr_dict
    
    @property
    def name(self) -> str:
        """CR metadata name."""
        return self._raw.get("metadata", {}).get("name", "")
    
    @property
    def domain_name(self) -> str:
        """Actual domain name from spec."""
        return self._raw.get("spec", {}).get("domainName", "")
    
    @property
    def owner(self) -> str:
        """Owner from labels."""
        return self._raw.get("metadata", {}).get("labels", {}).get("kubepanel.io/owner", "")
    
    @property
    def spec(self) -> dict:
        """Raw spec dict."""
        return self._raw.get("spec", {})
    
    @property
    def status(self) -> DomainStatus:
        """Parsed status."""
        return DomainStatus(self._raw.get("status"))
    
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

def create_domain(spec: DomainSpec, owner: str, labels: Optional[dict] = None) -> Domain:
    """
    Create a new Domain CR.
    
    Args:
        spec: DomainSpec with domain configuration
        owner: Username of the domain owner (stored in label)
        labels: Additional labels to add
    
    Returns:
        Created Domain object
    
    Raises:
        K8sConflictError: If domain already exists
        K8sValidationError: If spec is invalid
        K8sClientError: For other K8s errors
    """
    custom_api = get_custom_api()
    cr_name = _sanitize_cr_name(spec.domain_name)
    
    # Build labels
    all_labels = {
        "kubepanel.io/owner": owner,
        "app.kubernetes.io/managed-by": "kubepanel",
    }
    if labels:
        all_labels.update(labels)
    
    # Build CR
    domain_cr = {
        "apiVersion": f"{DOMAIN_GROUP}/{DOMAIN_VERSION}",
        "kind": "Domain",
        "metadata": {
            "name": cr_name,
            "labels": all_labels,
        },
        "spec": spec.to_dict(),
    }
    
    logger.info(f"Creating Domain CR '{cr_name}' for domain '{spec.domain_name}'")
    
    try:
        result = custom_api.create_cluster_custom_object(
            group=DOMAIN_GROUP,
            version=DOMAIN_VERSION,
            plural=DOMAIN_PLURAL,
            body=domain_cr,
        )
        logger.info(f"Created Domain CR '{cr_name}'")
        return Domain(result)
    except ApiException as e:
        handle_api_exception(e, f"Domain '{spec.domain_name}'")


def get_domain(domain_name: str) -> Domain:
    """
    Get a Domain CR by domain name.
    
    Args:
        domain_name: The domain name (e.g., 'example.com')
    
    Returns:
        Domain object
    
    Raises:
        K8sNotFoundError: If domain not found
        K8sClientError: For other K8s errors
    """
    custom_api = get_custom_api()
    cr_name = _sanitize_cr_name(domain_name)
    
    try:
        result = custom_api.get_cluster_custom_object(
            group=DOMAIN_GROUP,
            version=DOMAIN_VERSION,
            plural=DOMAIN_PLURAL,
            name=cr_name,
        )
        return Domain(result)
    except ApiException as e:
        handle_api_exception(e, f"Domain '{domain_name}'")


def get_domain_by_cr_name(cr_name: str) -> Domain:
    """
    Get a Domain CR by its CR name (metadata.name).
    
    Args:
        cr_name: The CR name (e.g., 'example-com')
    
    Returns:
        Domain object
    
    Raises:
        K8sNotFoundError: If domain not found
        K8sClientError: For other K8s errors
    """
    custom_api = get_custom_api()
    
    try:
        result = custom_api.get_cluster_custom_object(
            group=DOMAIN_GROUP,
            version=DOMAIN_VERSION,
            plural=DOMAIN_PLURAL,
            name=cr_name,
        )
        return Domain(result)
    except ApiException as e:
        handle_api_exception(e, f"Domain CR '{cr_name}'")


def list_domains(owner: Optional[str] = None) -> list[Domain]:
    """
    List Domain CRs, optionally filtered by owner.
    
    Args:
        owner: If provided, filter by owner label
    
    Returns:
        List of Domain objects
    
    Raises:
        K8sClientError: For K8s errors
    """
    custom_api = get_custom_api()
    
    label_selector = None
    if owner:
        label_selector = f"kubepanel.io/owner={owner}"
    
    try:
        result = custom_api.list_cluster_custom_object(
            group=DOMAIN_GROUP,
            version=DOMAIN_VERSION,
            plural=DOMAIN_PLURAL,
            label_selector=label_selector,
        )
        return [Domain(item) for item in result.get("items", [])]
    except ApiException as e:
        handle_api_exception(e, "Domain list")


def update_domain(domain_name: str, spec: DomainSpec) -> Domain:
    """
    Update a Domain CR's spec.
    
    Note: domainName is immutable and cannot be changed.
    
    Args:
        domain_name: The domain name to update
        spec: New DomainSpec (domainName must match)
    
    Returns:
        Updated Domain object
    
    Raises:
        K8sNotFoundError: If domain not found
        K8sValidationError: If spec is invalid
        K8sClientError: For other K8s errors
    """
    custom_api = get_custom_api()
    cr_name = _sanitize_cr_name(domain_name)
    
    # Get current CR to preserve metadata
    current = get_domain(domain_name)
    
    # Build updated CR (preserve metadata, update spec)
    updated_cr = current.to_dict()
    updated_cr["spec"] = spec.to_dict()
    
    logger.info(f"Updating Domain CR '{cr_name}'")
    
    try:
        result = custom_api.replace_cluster_custom_object(
            group=DOMAIN_GROUP,
            version=DOMAIN_VERSION,
            plural=DOMAIN_PLURAL,
            name=cr_name,
            body=updated_cr,
        )
        logger.info(f"Updated Domain CR '{cr_name}'")
        return Domain(result)
    except ApiException as e:
        handle_api_exception(e, f"Domain '{domain_name}'")


def patch_domain(domain_name: str, patch: dict) -> Domain:
    """
    Patch a Domain CR's spec (partial update).
    
    Args:
        domain_name: The domain name to patch
        patch: Dict with fields to update (merged with existing spec)
    
    Returns:
        Updated Domain object
    
    Raises:
        K8sNotFoundError: If domain not found
        K8sClientError: For other K8s errors
    """
    custom_api = get_custom_api()
    cr_name = _sanitize_cr_name(domain_name)
    
    patch_body = {"spec": patch}
    
    logger.info(f"Patching Domain CR '{cr_name}'")
    
    try:
        result = custom_api.patch_cluster_custom_object(
            group=DOMAIN_GROUP,
            version=DOMAIN_VERSION,
            plural=DOMAIN_PLURAL,
            name=cr_name,
            body=patch_body,
        )
        logger.info(f"Patched Domain CR '{cr_name}'")
        return Domain(result)
    except ApiException as e:
        handle_api_exception(e, f"Domain '{domain_name}'")


def delete_domain(domain_name: str) -> None:
    """
    Delete a Domain CR.
    
    The operator will handle cleanup of associated resources.
    
    Args:
        domain_name: The domain name to delete
    
    Raises:
        K8sNotFoundError: If domain not found
        K8sClientError: For other K8s errors
    """
    custom_api = get_custom_api()
    cr_name = _sanitize_cr_name(domain_name)
    
    logger.info(f"Deleting Domain CR '{cr_name}'")
    
    try:
        custom_api.delete_cluster_custom_object(
            group=DOMAIN_GROUP,
            version=DOMAIN_VERSION,
            plural=DOMAIN_PLURAL,
            name=cr_name,
        )
        logger.info(f"Deleted Domain CR '{cr_name}'")
    except ApiException as e:
        handle_api_exception(e, f"Domain '{domain_name}'")


def suspend_domain(domain_name: str) -> Domain:
    """
    Suspend a domain (scales workloads to zero).
    
    Args:
        domain_name: The domain name to suspend
    
    Returns:
        Updated Domain object
    """
    return patch_domain(domain_name, {"suspended": True})


def unsuspend_domain(domain_name: str) -> Domain:
    """
    Unsuspend a domain (restores workloads).
    
    Args:
        domain_name: The domain name to unsuspend
    
    Returns:
        Updated Domain object
    """
    return patch_domain(domain_name, {"suspended": False})


def domain_exists(domain_name: str) -> bool:
    """
    Check if a domain exists.

    Args:
        domain_name: The domain name to check

    Returns:
        True if exists, False otherwise
    """
    try:
        get_domain(domain_name)
        return True
    except K8sNotFoundError:
        return False


def get_dns_status(domain_name: str) -> dict:
    """
    Get DNS status from Domain CR.

    Args:
        domain_name: The domain name

    Returns:
        Dict with DNS status:
        - phase: Ready/Provisioning/Failed
        - zone: {id, name}
        - records: List of record status dicts

    Raises:
        K8sNotFoundError: If domain not found
        K8sClientError: For other K8s errors
    """
    domain = get_domain(domain_name)
    return domain.status._raw.get("dns", {})


def add_dns_record(domain_name: str, record: dict) -> Domain:
    """
    Add a DNS record to Domain CR spec.

    Args:
        domain_name: The domain name
        record: Record dict with type, name, content, ttl, proxied, priority

    Returns:
        Updated Domain object
    """
    domain = get_domain(domain_name)
    current_dns = domain.spec.get("dns", {})
    records = current_dns.get("records", [])

    records.append(record)

    return patch_domain(domain_name, {
        "dns": {
            **current_dns,
            "records": records
        }
    })


def update_dns_record(domain_name: str, record_index: int, record: dict) -> Domain:
    """
    Update a DNS record in Domain CR spec.

    Args:
        domain_name: The domain name
        record_index: Index of the record in spec.dns.records
        record: Updated record dict

    Returns:
        Updated Domain object
    """
    domain = get_domain(domain_name)
    current_dns = domain.spec.get("dns", {})
    records = list(current_dns.get("records", []))

    if 0 <= record_index < len(records):
        records[record_index] = record
    else:
        raise K8sClientError(f"Record index {record_index} out of range")

    return patch_domain(domain_name, {
        "dns": {
            **current_dns,
            "records": records
        }
    })


def delete_dns_record_from_cr(domain_name: str, record_index: int) -> Domain:
    """
    Delete a DNS record from Domain CR spec.

    Args:
        domain_name: The domain name
        record_index: Index of the record to delete

    Returns:
        Updated Domain object
    """
    domain = get_domain(domain_name)
    current_dns = domain.spec.get("dns", {})
    records = list(current_dns.get("records", []))

    if 0 <= record_index < len(records):
        records.pop(record_index)
    else:
        raise K8sClientError(f"Record index {record_index} out of range")

    return patch_domain(domain_name, {
        "dns": {
            **current_dns,
            "records": records
        }
    })


def get_domain_config(domain_name: str) -> dict:
    """
    Get domain configuration from CR spec.

    Returns a flat dict with all config values that can be used
    to populate edit forms. This is the single source of truth
    for infrastructure configuration.

    Args:
        domain_name: The domain name

    Returns:
        Dict with config values:
        - php_memory_limit
        - php_max_execution_time
        - php_upload_max_filesize
        - php_post_max_size
        - custom_php_config
        - document_root
        - client_max_body_size
        - ssl_redirect
        - www_redirect
        - custom_nginx_config

    Raises:
        K8sNotFoundError: If domain not found
        K8sClientError: For other K8s errors
    """
    domain = get_domain(domain_name)
    spec = domain.spec

    # Extract PHP settings
    php = spec.get("php", {})
    php_settings = php.get("settings", {})

    # Extract webserver settings
    webserver = spec.get("webserver", {})

    return {
        # PHP settings
        "php_memory_limit": php_settings.get("memoryLimit", "256M"),
        "php_max_execution_time": php_settings.get("maxExecutionTime", 30),
        "php_upload_max_filesize": php_settings.get("uploadMaxFilesize", "64M"),
        "php_post_max_size": php_settings.get("postMaxSize", "64M"),
        "custom_php_config": php.get("customConfig", ""),

        # Webserver settings
        "document_root": webserver.get("documentRoot", "/public_html"),
        "client_max_body_size": webserver.get("clientMaxBodySize", "64m"),
        "ssl_redirect": webserver.get("sslRedirect", True),
        "www_redirect": webserver.get("wwwRedirect", "none"),
        "custom_nginx_config": webserver.get("customConfig", ""),
    }
