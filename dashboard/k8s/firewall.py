"""
Kubernetes Firewall Rules Management

Syncs ModSecurity rules to ingress-nginx ConfigMap.
"""

import logging
from kubernetes.client.rest import ApiException

from .client import get_core_api, handle_api_exception, K8sClientError

logger = logging.getLogger(__name__)

# ingress-nginx ConfigMap location
INGRESS_NAMESPACE = "ingress"
INGRESS_CONFIGMAP_NAME = "nginx-load-balancer-microk8s-conf"


def sync_modsecurity_rules(rules_content: str) -> None:
    """
    Sync ModSecurity rules to the ingress-nginx ConfigMap.

    Updates the 'modsecurity-snippet' key in the ConfigMap.
    The ingress-nginx controller will auto-reload when the ConfigMap changes.

    Args:
        rules_content: The ModSecurity rules as a string (multiple rules separated by newlines)

    Raises:
        K8sNotFoundError: If ConfigMap not found
        K8sClientError: For other K8s errors
    """
    core_api = get_core_api()

    try:
        # Read current ConfigMap
        configmap = core_api.read_namespaced_config_map(
            name=INGRESS_CONFIGMAP_NAME,
            namespace=INGRESS_NAMESPACE
        )

        # Update modsecurity-snippet
        if configmap.data is None:
            configmap.data = {}

        if rules_content.strip():
            configmap.data["modsecurity-snippet"] = rules_content
            logger.info(f"Setting modsecurity-snippet with {len(rules_content)} chars")
        else:
            # Remove the key if no rules
            configmap.data.pop("modsecurity-snippet", None)
            logger.info("Removing modsecurity-snippet (no rules)")

        # Patch the ConfigMap
        core_api.patch_namespaced_config_map(
            name=INGRESS_CONFIGMAP_NAME,
            namespace=INGRESS_NAMESPACE,
            body=configmap
        )

        logger.info(f"Successfully synced ModSecurity rules to ConfigMap {INGRESS_NAMESPACE}/{INGRESS_CONFIGMAP_NAME}")

    except ApiException as e:
        handle_api_exception(e, f"ConfigMap {INGRESS_NAMESPACE}/{INGRESS_CONFIGMAP_NAME}")


def get_current_modsecurity_rules() -> str:
    """
    Get current ModSecurity rules from the ingress-nginx ConfigMap.

    Returns:
        The modsecurity-snippet content, or empty string if not set

    Raises:
        K8sNotFoundError: If ConfigMap not found
        K8sClientError: For other K8s errors
    """
    core_api = get_core_api()

    try:
        configmap = core_api.read_namespaced_config_map(
            name=INGRESS_CONFIGMAP_NAME,
            namespace=INGRESS_NAMESPACE
        )

        if configmap.data:
            return configmap.data.get("modsecurity-snippet", "")
        return ""

    except ApiException as e:
        handle_api_exception(e, f"ConfigMap {INGRESS_NAMESPACE}/{INGRESS_CONFIGMAP_NAME}")
