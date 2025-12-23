"""
Restore CR Operations

Functions to manage KubePanel Restore custom resources.
"""

from dataclasses import dataclass
from typing import Optional
from datetime import datetime
from kubernetes.client.rest import ApiException
import logging

from .client import (
    get_custom_api,
    handle_api_exception,
    K8sClientError,
)

logger = logging.getLogger(__name__)

# CRD constants
RESTORE_GROUP = 'kubepanel.io'
RESTORE_VERSION = 'v1alpha1'
RESTORE_PLURAL = 'restores'


@dataclass
class RestoreStatus:
    """Status of a Restore CR."""
    phase: str
    message: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> 'RestoreStatus':
        """Create RestoreStatus from K8s status dict."""
        return cls(
            phase=data.get('phase', 'Unknown'),
            message=data.get('message'),
            started_at=data.get('startedAt'),
            completed_at=data.get('completedAt'),
        )


@dataclass
class Restore:
    """Represents a KubePanel Restore CR."""
    name: str
    namespace: str
    domain_name: str
    backup_name: str
    volume_snapshot_name: str
    database_backup_path: str
    created_at: str
    status: RestoreStatus

    @classmethod
    def from_dict(cls, data: dict) -> 'Restore':
        """Create Restore from K8s resource dict."""
        metadata = data.get('metadata', {})
        spec = data.get('spec', {})
        status_data = data.get('status', {})

        return cls(
            name=metadata.get('name', ''),
            namespace=metadata.get('namespace', ''),
            domain_name=spec.get('domainName', ''),
            backup_name=spec.get('backupName', ''),
            volume_snapshot_name=spec.get('volumeSnapshotName', ''),
            database_backup_path=spec.get('databaseBackupPath', ''),
            created_at=metadata.get('creationTimestamp', ''),
            status=RestoreStatus.from_dict(status_data),
        )


def list_restores(namespace: str) -> list[Restore]:
    """
    List all Restore CRs in a namespace.

    Args:
        namespace: Kubernetes namespace (e.g., 'dom-example-com')

    Returns:
        List of Restore objects sorted by creation time (newest first)
    """
    custom_api = get_custom_api()

    try:
        result = custom_api.list_namespaced_custom_object(
            group=RESTORE_GROUP,
            version=RESTORE_VERSION,
            namespace=namespace,
            plural=RESTORE_PLURAL,
        )

        restores = [Restore.from_dict(item) for item in result.get('items', [])]
        # Sort by creation time, newest first
        restores.sort(key=lambda r: r.created_at, reverse=True)
        return restores

    except ApiException as e:
        if e.status == 404:
            return []  # Namespace doesn't exist or no restores
        handle_api_exception(e, f"Restore list in {namespace}")
        return []


def get_restore(namespace: str, name: str) -> Optional[Restore]:
    """
    Get a specific Restore CR.

    Args:
        namespace: Kubernetes namespace
        name: Restore CR name

    Returns:
        Restore object or None if not found
    """
    custom_api = get_custom_api()

    try:
        result = custom_api.get_namespaced_custom_object(
            group=RESTORE_GROUP,
            version=RESTORE_VERSION,
            namespace=namespace,
            plural=RESTORE_PLURAL,
            name=name,
        )
        return Restore.from_dict(result)

    except ApiException as e:
        if e.status == 404:
            return None
        handle_api_exception(e, f"Restore {name}")
        return None


def create_restore(
    namespace: str,
    domain_name: str,
    backup_name: str,
    volume_snapshot_name: str,
    database_backup_path: str,
) -> Restore:
    """
    Create a new Restore CR.

    Args:
        namespace: Kubernetes namespace for the domain
        domain_name: Domain name (e.g., 'example.com')
        backup_name: Name of the Backup CR to restore from
        volume_snapshot_name: Name of the VolumeSnapshot to restore
        database_backup_path: Path to the database dump file

    Returns:
        Created Restore object

    Raises:
        K8sClientError: If creation fails
    """
    custom_api = get_custom_api()

    # Generate restore name with timestamp
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    cr_name = domain_name.replace('.', '-')
    restore_name = f"{cr_name}-restore-{timestamp}"

    restore_cr = {
        'apiVersion': f'{RESTORE_GROUP}/{RESTORE_VERSION}',
        'kind': 'Restore',
        'metadata': {
            'name': restore_name,
            'namespace': namespace,
            'labels': {
                'kubepanel.io/domain': cr_name,
                'kubepanel.io/backup': backup_name,
            },
        },
        'spec': {
            'domainName': domain_name,
            'backupName': backup_name,
            'volumeSnapshotName': volume_snapshot_name,
            'databaseBackupPath': database_backup_path,
        },
    }

    try:
        result = custom_api.create_namespaced_custom_object(
            group=RESTORE_GROUP,
            version=RESTORE_VERSION,
            namespace=namespace,
            plural=RESTORE_PLURAL,
            body=restore_cr,
        )
        logger.info(f"Created Restore CR {restore_name} in {namespace}")
        return Restore.from_dict(result)

    except ApiException as e:
        handle_api_exception(e, f"Restore {restore_name}")
        raise K8sClientError(f"Failed to create restore: {e}")


def delete_restore(namespace: str, name: str) -> bool:
    """
    Delete a Restore CR.

    Args:
        namespace: Kubernetes namespace
        name: Restore CR name

    Returns:
        True if deleted, False if not found
    """
    custom_api = get_custom_api()

    try:
        custom_api.delete_namespaced_custom_object(
            group=RESTORE_GROUP,
            version=RESTORE_VERSION,
            namespace=namespace,
            plural=RESTORE_PLURAL,
            name=name,
        )
        logger.info(f"Deleted Restore CR {name} from {namespace}")
        return True

    except ApiException as e:
        if e.status == 404:
            return False
        handle_api_exception(e, f"Restore {name}")
        return False
