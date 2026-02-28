"""
Backup CR Operations

Functions to manage KubePanel Backup custom resources.
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
BACKUP_GROUP = 'kubepanel.io'
BACKUP_VERSION = 'v1alpha1'
BACKUP_PLURAL = 'backups'


@dataclass
class BackupStatus:
    """Status of a Backup CR."""
    phase: str
    message: Optional[str] = None
    volume_snapshot_name: Optional[str] = None
    database_backup_path: Optional[str] = None
    size_bytes: Optional[int] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    retention_expires_at: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> 'BackupStatus':
        """Create BackupStatus from K8s status dict."""
        return cls(
            phase=data.get('phase', 'Unknown'),
            message=data.get('message'),
            volume_snapshot_name=data.get('volumeSnapshotName'),
            database_backup_path=data.get('databaseBackupPath'),
            size_bytes=data.get('sizeBytes'),
            started_at=data.get('startedAt'),
            completed_at=data.get('completedAt'),
            retention_expires_at=data.get('retentionExpiresAt'),
        )


@dataclass
class Backup:
    """Represents a KubePanel Backup CR."""
    name: str
    namespace: str
    domain_name: str
    backup_type: str  # 'scheduled' or 'manual'
    created_at: str
    status: BackupStatus

    @classmethod
    def from_dict(cls, data: dict) -> 'Backup':
        """Create Backup from K8s resource dict."""
        metadata = data.get('metadata', {})
        spec = data.get('spec', {})
        status_data = data.get('status', {})

        return cls(
            name=metadata.get('name', ''),
            namespace=metadata.get('namespace', ''),
            domain_name=spec.get('domainName', ''),
            backup_type=spec.get('type', 'manual'),
            created_at=metadata.get('creationTimestamp', ''),
            status=BackupStatus.from_dict(status_data),
        )

    @property
    def size_display(self) -> str:
        """Human-readable size."""
        if not self.status.size_bytes:
            return '-'
        size = self.status.size_bytes
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"


def list_backups(namespace: str) -> list[Backup]:
    """
    List all Backup CRs in a namespace.

    Args:
        namespace: Kubernetes namespace (e.g., 'dom-example-com')

    Returns:
        List of Backup objects sorted by creation time (newest first)
    """
    custom_api = get_custom_api()

    try:
        result = custom_api.list_namespaced_custom_object(
            group=BACKUP_GROUP,
            version=BACKUP_VERSION,
            namespace=namespace,
            plural=BACKUP_PLURAL,
        )

        backups = [Backup.from_dict(item) for item in result.get('items', [])]
        # Sort by creation time, newest first
        backups.sort(key=lambda b: b.created_at, reverse=True)
        return backups

    except ApiException as e:
        if e.status == 404:
            return []  # Namespace doesn't exist or no backups
        handle_api_exception(e, f"Backup list in {namespace}")
        return []


def get_backup(namespace: str, name: str) -> Optional[Backup]:
    """
    Get a specific Backup CR.

    Args:
        namespace: Kubernetes namespace
        name: Backup CR name

    Returns:
        Backup object or None if not found
    """
    custom_api = get_custom_api()

    try:
        result = custom_api.get_namespaced_custom_object(
            group=BACKUP_GROUP,
            version=BACKUP_VERSION,
            namespace=namespace,
            plural=BACKUP_PLURAL,
            name=name,
        )
        return Backup.from_dict(result)

    except ApiException as e:
        if e.status == 404:
            return None
        handle_api_exception(e, f"Backup {name}")
        return None


def create_backup(
    namespace: str,
    domain_name: str,
    backup_type: str = 'manual',
) -> Backup:
    """
    Create a new Backup CR.

    Args:
        namespace: Kubernetes namespace for the domain
        domain_name: Domain name (e.g., 'example.com')
        backup_type: 'manual' or 'scheduled'

    Returns:
        Created Backup object

    Raises:
        K8sClientError: If creation fails
    """
    custom_api = get_custom_api()

    # Generate backup name with timestamp
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    cr_name = domain_name.replace('.', '-')
    backup_name = f"{cr_name}-{timestamp}"

    backup_cr = {
        'apiVersion': f'{BACKUP_GROUP}/{BACKUP_VERSION}',
        'kind': 'Backup',
        'metadata': {
            'name': backup_name,
            'namespace': namespace,
            'labels': {
                'kubepanel.io/domain': cr_name,
                'kubepanel.io/backup-type': backup_type,
            },
        },
        'spec': {
            'domainName': domain_name,
            'type': backup_type,
        },
    }

    try:
        result = custom_api.create_namespaced_custom_object(
            group=BACKUP_GROUP,
            version=BACKUP_VERSION,
            namespace=namespace,
            plural=BACKUP_PLURAL,
            body=backup_cr,
        )
        logger.info(f"Created Backup CR {backup_name} in {namespace}")
        return Backup.from_dict(result)

    except ApiException as e:
        handle_api_exception(e, f"Backup {backup_name}")
        raise K8sClientError(f"Failed to create backup: {e}")


def delete_backup(namespace: str, name: str) -> bool:
    """
    Delete a Backup CR.

    Args:
        namespace: Kubernetes namespace
        name: Backup CR name

    Returns:
        True if deleted, False if not found
    """
    custom_api = get_custom_api()

    try:
        custom_api.delete_namespaced_custom_object(
            group=BACKUP_GROUP,
            version=BACKUP_VERSION,
            namespace=namespace,
            plural=BACKUP_PLURAL,
            name=name,
        )
        logger.info(f"Deleted Backup CR {name} from {namespace}")
        return True

    except ApiException as e:
        if e.status == 404:
            return False
        handle_api_exception(e, f"Backup {name}")
        return False
