"""
Kubernetes Client

Singleton wrapper for Kubernetes API client.
Handles both in-cluster and local kubeconfig authentication.
"""

from kubernetes import client, config
from kubernetes.client.rest import ApiException
import logging
import os
from functools import lru_cache

logger = logging.getLogger(__name__)


class K8sClientError(Exception):
    """Base exception for K8s client errors."""
    pass


class K8sConnectionError(K8sClientError):
    """Failed to connect to Kubernetes API."""
    pass


class K8sNotFoundError(K8sClientError):
    """Resource not found."""
    pass


class K8sConflictError(K8sClientError):
    """Resource already exists or conflict."""
    pass


class K8sValidationError(K8sClientError):
    """Resource validation failed."""
    pass


@lru_cache(maxsize=1)
def get_k8s_clients() -> tuple[client.CoreV1Api, client.CustomObjectsApi]:
    """
    Get Kubernetes API clients (cached singleton).
    
    Tries in-cluster config first, falls back to kubeconfig.
    
    Returns:
        Tuple of (CoreV1Api, CustomObjectsApi)
    
    Raises:
        K8sConnectionError: If unable to connect to cluster
    """
    try:
        # Try in-cluster config first (when running in a pod)
        config.load_incluster_config()
        logger.info("Using in-cluster Kubernetes config")
    except config.ConfigException:
        try:
            # Fall back to kubeconfig (local development)
            kubeconfig_path = os.environ.get('KUBECONFIG', '~/.kube/config')
            config.load_kube_config(config_file=os.path.expanduser(kubeconfig_path))
            logger.info(f"Using kubeconfig from {kubeconfig_path}")
        except config.ConfigException as e:
            raise K8sConnectionError(f"Failed to load Kubernetes config: {e}")
    
    return client.CoreV1Api(), client.CustomObjectsApi()


def get_core_api() -> client.CoreV1Api:
    """Get CoreV1Api client."""
    core_api, _ = get_k8s_clients()
    return core_api


def get_custom_api() -> client.CustomObjectsApi:
    """Get CustomObjectsApi client."""
    _, custom_api = get_k8s_clients()
    return custom_api


def handle_api_exception(e: ApiException, resource_name: str = "resource") -> None:
    """
    Convert Kubernetes ApiException to our custom exceptions.
    
    Args:
        e: The ApiException from kubernetes client
        resource_name: Name of the resource for error messages
    
    Raises:
        K8sNotFoundError: If resource not found (404)
        K8sConflictError: If resource already exists (409)
        K8sValidationError: If validation failed (422)
        K8sClientError: For other errors
    """
    if e.status == 404:
        raise K8sNotFoundError(f"{resource_name} not found")
    elif e.status == 409:
        raise K8sConflictError(f"{resource_name} already exists")
    elif e.status == 422:
        raise K8sValidationError(f"Validation failed for {resource_name}: {e.reason}")
    else:
        raise K8sClientError(f"Kubernetes API error for {resource_name}: {e.reason}")
