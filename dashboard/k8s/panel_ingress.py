"""
Panel Ingress Management

Manages the KubePanel dashboard Ingress for adding/removing additional domain names.
Also updates Django settings.py ALLOWED_HOSTS and CSRF_TRUSTED_ORIGINS.
"""

from kubernetes import client, config
from kubernetes.client.rest import ApiException
import logging
import re
from pathlib import Path

from .client import K8sClientError, K8sNotFoundError

logger = logging.getLogger(__name__)

NAMESPACE = 'kubepanel'
INGRESS_NAME = 'ingress'

# Always kept in ALLOWED_HOSTS regardless of Ingress configuration -
# in-cluster clients (Fluent Bit analytics ingest) reach the panel
# through the service, not through the Ingress.
INTERNAL_HOSTS = ['kubepanel.kubepanel.svc.cluster.local']


def _get_networking_api() -> client.NetworkingV1Api:
    """Get NetworkingV1Api client."""
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.NetworkingV1Api()


def get_panel_hosts() -> list[str]:
    """
    Get current hosts from the kubepanel dashboard Ingress.

    Returns:
        List of host names configured in the Ingress
    """
    networking = _get_networking_api()
    try:
        ingress = networking.read_namespaced_ingress(INGRESS_NAME, NAMESPACE)
        hosts = []
        if ingress.spec.rules:
            for rule in ingress.spec.rules:
                if rule.host:
                    hosts.append(rule.host)
        return hosts
    except ApiException as e:
        if e.status == 404:
            raise K8sNotFoundError(f"Ingress '{INGRESS_NAME}' not found in namespace '{NAMESPACE}'")
        raise K8sClientError(f"Failed to read Ingress: {e.reason}")


def get_primary_domain() -> str:
    """
    Get the primary (first) domain from the Ingress.

    Returns:
        The primary domain name
    """
    hosts = get_panel_hosts()
    if hosts:
        return hosts[0]
    return ''


def add_panel_domain(domain_name: str) -> None:
    """
    Add a new domain to the kubepanel dashboard Ingress.

    Creates a new rule and TLS entry for the domain.
    Also updates Django settings.py with the new domain.

    Args:
        domain_name: The domain name to add (e.g., 'panel.example.com')

    Raises:
        K8sClientError: If unable to patch the Ingress
        ValueError: If domain already exists
    """
    domain_name = domain_name.lower().strip()

    networking = _get_networking_api()

    try:
        ingress = networking.read_namespaced_ingress(INGRESS_NAME, NAMESPACE)
    except ApiException as e:
        if e.status == 404:
            raise K8sNotFoundError(f"Ingress '{INGRESS_NAME}' not found")
        raise K8sClientError(f"Failed to read Ingress: {e.reason}")

    # Check if domain already exists
    existing_hosts = [rule.host for rule in (ingress.spec.rules or []) if rule.host]
    if domain_name in existing_hosts:
        raise ValueError(f"Domain '{domain_name}' already exists in Ingress")

    # Build secret name for TLS (replace dots with dashes)
    secret_name = f"kubepanel-cert-{domain_name.replace('.', '-')}"

    # Build the new rule
    new_rule = {
        "host": domain_name,
        "http": {
            "paths": [{
                "path": "/",
                "pathType": "Prefix",
                "backend": {
                    "service": {
                        "name": "kubepanel",
                        "port": {"number": 8000}
                    }
                }
            }]
        }
    }

    # Build the new TLS entry
    new_tls = {
        "hosts": [domain_name],
        "secretName": secret_name
    }

    # Serialize existing rules
    rules = []
    for rule in (ingress.spec.rules or []):
        rules.append({
            "host": rule.host,
            "http": {
                "paths": [{
                    "path": path.path,
                    "pathType": path.path_type,
                    "backend": {
                        "service": {
                            "name": path.backend.service.name,
                            "port": {"number": path.backend.service.port.number}
                        }
                    }
                } for path in rule.http.paths]
            }
        })
    rules.append(new_rule)

    # Serialize existing TLS
    tls = []
    for entry in (ingress.spec.tls or []):
        tls.append({
            "hosts": entry.hosts,
            "secretName": entry.secret_name
        })
    tls.append(new_tls)

    # Patch the Ingress
    patch_body = {"spec": {"rules": rules, "tls": tls}}

    try:
        networking.patch_namespaced_ingress(
            name=INGRESS_NAME,
            namespace=NAMESPACE,
            body=patch_body
        )
        logger.info(f"Added domain '{domain_name}' to kubepanel Ingress")
    except ApiException as e:
        raise K8sClientError(f"Failed to patch Ingress: {e.reason}")

    # Update Django settings.py
    all_hosts = existing_hosts + [domain_name]
    _update_settings_file(all_hosts)


def remove_panel_domain(domain_name: str) -> None:
    """
    Remove a domain from the kubepanel dashboard Ingress.

    Also updates Django settings.py to remove the domain.

    Args:
        domain_name: The domain name to remove

    Raises:
        K8sClientError: If unable to patch the Ingress
        ValueError: If trying to remove the primary domain or domain not found
    """
    domain_name = domain_name.lower().strip()

    networking = _get_networking_api()

    try:
        ingress = networking.read_namespaced_ingress(INGRESS_NAME, NAMESPACE)
    except ApiException as e:
        if e.status == 404:
            raise K8sNotFoundError(f"Ingress '{INGRESS_NAME}' not found")
        raise K8sClientError(f"Failed to read Ingress: {e.reason}")

    # Get existing hosts
    existing_hosts = [rule.host for rule in (ingress.spec.rules or []) if rule.host]

    # Check if domain exists
    if domain_name not in existing_hosts:
        raise ValueError(f"Domain '{domain_name}' not found in Ingress")

    # Prevent removing the primary (first) domain
    if existing_hosts and existing_hosts[0] == domain_name:
        raise ValueError("Cannot remove the primary domain")

    # Filter out the domain from rules
    rules = []
    for rule in (ingress.spec.rules or []):
        if rule.host != domain_name:
            rules.append({
                "host": rule.host,
                "http": {
                    "paths": [{
                        "path": path.path,
                        "pathType": path.path_type,
                        "backend": {
                            "service": {
                                "name": path.backend.service.name,
                                "port": {"number": path.backend.service.port.number}
                            }
                        }
                    } for path in rule.http.paths]
                }
            })

    # Filter out the domain from TLS
    tls = []
    for entry in (ingress.spec.tls or []):
        if domain_name not in (entry.hosts or []):
            tls.append({
                "hosts": entry.hosts,
                "secretName": entry.secret_name
            })

    # Patch the Ingress
    patch_body = {"spec": {"rules": rules, "tls": tls}}

    try:
        networking.patch_namespaced_ingress(
            name=INGRESS_NAME,
            namespace=NAMESPACE,
            body=patch_body
        )
        logger.info(f"Removed domain '{domain_name}' from kubepanel Ingress")
    except ApiException as e:
        raise K8sClientError(f"Failed to patch Ingress: {e.reason}")

    # Update Django settings.py
    remaining_hosts = [h for h in existing_hosts if h != domain_name]
    _update_settings_file(remaining_hosts)


def _update_settings_file(hosts: list[str]) -> None:
    """
    Update ALLOWED_HOSTS and CSRF_TRUSTED_ORIGINS in Django settings.py.

    Args:
        hosts: List of all hosts to include in settings
    """
    settings_path = Path(__file__).resolve().parent.parent.parent / 'kubepanel' / 'settings.py'

    if not settings_path.exists():
        logger.warning(f"Settings file not found at {settings_path}")
        return

    try:
        content = settings_path.read_text()

        # Build the new values. The in-cluster service name must always be
        # allowed - Fluent Bit posts analytics data to the service directly.
        all_hosts = list(hosts)
        for internal_host in INTERNAL_HOSTS:
            if internal_host not in all_hosts:
                all_hosts.append(internal_host)
        hosts_str = ', '.join(f'"{h}"' for h in all_hosts)
        allowed_hosts_line = f'ALLOWED_HOSTS = [{hosts_str}]'

        csrf_origins = [f'"https://{h}"' for h in hosts]
        csrf_str = ', '.join(csrf_origins)
        csrf_line = f'CSRF_TRUSTED_ORIGINS = [{csrf_str}]'

        # Replace ALLOWED_HOSTS line
        content = re.sub(
            r'^ALLOWED_HOSTS\s*=\s*\[.*?\]',
            allowed_hosts_line,
            content,
            flags=re.MULTILINE
        )

        # Replace CSRF_TRUSTED_ORIGINS line
        content = re.sub(
            r'^CSRF_TRUSTED_ORIGINS\s*=\s*\[.*?\]',
            csrf_line,
            content,
            flags=re.MULTILINE
        )

        settings_path.write_text(content)
        logger.info(f"Updated settings.py with hosts: {hosts}")

    except Exception as e:
        logger.error(f"Failed to update settings.py: {e}")
        raise K8sClientError(f"Failed to update settings.py: {e}")
