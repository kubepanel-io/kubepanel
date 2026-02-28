"""
Migration Job Management

Creates and manages Kubernetes Jobs for cPanel migration batches.
"""

import logging
import os
from typing import Optional

from django.conf import settings
from kubernetes import client, config
from kubernetes.client import ApiException

from .migration_sftp import create_migration_sftp, get_sftp_container_spec

logger = logging.getLogger(__name__)

# Default image for migration worker
DEFAULT_MIGRATION_IMAGE = os.environ.get(
    'MIGRATION_WORKER_IMAGE',
    'kubepanel/migration-worker:v1.0'
)

# Namespace for migration jobs
MIGRATION_NAMESPACE = os.environ.get('KUBEPANEL_NAMESPACE', 'kubepanel')


def _load_k8s_config():
    """Load Kubernetes configuration."""
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()


def create_migration_job(batch_id: int, image: str = None) -> str:
    """
    Create a Kubernetes Job to process a migration batch.

    This also creates the SFTP infrastructure for receiving backups
    from the source cPanel server.

    Args:
        batch_id: The MigrationBatch ID to process
        image: Optional custom image URL

    Returns:
        Job name
    """
    # Import here to avoid circular imports
    from dashboard.models import MigrationBatch

    # Create SFTP receiver first
    logger.info(f"Creating SFTP infrastructure for batch {batch_id}")
    sftp_info = create_migration_sftp(batch_id)

    # Get public hostname from Django settings
    hostname = settings.ALLOWED_HOSTS[0] if settings.ALLOWED_HOSTS else 'localhost'

    # Update batch with SFTP info
    batch = MigrationBatch.objects.get(id=batch_id)
    batch.sftp_port = sftp_info['port']
    batch.sftp_username = sftp_info['username']
    batch.sftp_password = sftp_info['password']
    batch.sftp_hostname = hostname
    batch.save()
    logger.info(f"Saved SFTP info to batch: port={sftp_info['port']}, host={hostname}")

    _load_k8s_config()
    batch_v1 = client.BatchV1Api()

    job_name = f"migration-batch-{batch_id}"
    image = image or DEFAULT_MIGRATION_IMAGE
    sftp_pvc_name = f"migration-sftp-{batch_id}"

    # Get environment variables from secrets
    env_vars = [
        {
            "name": "BATCH_ID",
            "value": str(batch_id),
        },
        {
            "name": "DATABASE_URL",
            "valueFrom": {
                "secretKeyRef": {
                    "name": "kubepanel-db",
                    "key": "DATABASE_URL",
                    "optional": True,
                }
            }
        },
        {
            "name": "DJANGO_SETTINGS_MODULE",
            "value": "kubepanel.settings",
        },
        {
            "name": "DJANGO_SECRET_KEY",
            "valueFrom": {
                "secretKeyRef": {
                    "name": "kubepanel-secrets",
                    "key": "django-secret-key",
                }
            }
        },
        # SFTP configuration for backup push
        {
            "name": "SFTP_HOST",
            "value": hostname,
        },
        {
            "name": "SFTP_PORT",
            "value": str(sftp_info['port']),
        },
        {
            "name": "SFTP_USER",
            "value": sftp_info['username'],
        },
        {
            "name": "SFTP_PASSWORD",
            "value": sftp_info['password'],
        },
    ]

    # Get SFTP sidecar container spec
    sftp_container = get_sftp_container_spec(
        batch_id=batch_id,
        username=sftp_info['username'],
        password=sftp_info['password'],
    )

    job_spec = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": job_name,
            "namespace": MIGRATION_NAMESPACE,
            "labels": {
                "app": "cpanel-migration",
                "batch-id": str(batch_id),
            },
        },
        "spec": {
            "ttlSecondsAfterFinished": 3600,  # Cleanup after 1 hour
            "backoffLimit": 0,  # Don't retry on failure
            "template": {
                "metadata": {
                    "labels": {
                        "app": "cpanel-migration",
                        "batch-id": str(batch_id),
                    },
                },
                "spec": {
                    "restartPolicy": "Never",
                    # Use the kubepanel service account for K8s API access
                    "serviceAccountName": "kubepanel",
                    # Set fsGroup so mounted volumes are writable by gid 1000 (SSH user)
                    "securityContext": {
                        "fsGroup": 1000,
                    },
                    # Schedule on same node as kubepanel deployment (required for RWO PVC)
                    "affinity": {
                        "podAffinity": {
                            "requiredDuringSchedulingIgnoredDuringExecution": [{
                                "labelSelector": {
                                    "matchLabels": {
                                        "app": "kubepanel",
                                    },
                                },
                                "topologyKey": "kubernetes.io/hostname",
                            }],
                        },
                    },
                    "containers": [
                        # Main migration worker container
                        {
                            "name": "migrator",
                            "image": image,
                            "env": env_vars,
                            # Run as root to match SFTP container for shared PVC access
                            "securityContext": {
                                "runAsUser": 0,
                                "runAsGroup": 0,
                            },
                            "resources": {
                                "requests": {
                                    "memory": "512Mi",
                                    "cpu": "500m",
                                },
                                "limits": {
                                    "memory": "2Gi",
                                    "cpu": "2",
                                },
                            },
                            "volumeMounts": [
                                {
                                    "name": "temp",
                                    "mountPath": "/tmp/migration",
                                },
                                {
                                    "name": "kubepanel",
                                    "mountPath": "/kubepanel",
                                    "readOnly": True,
                                },
                                {
                                    "name": "sftp-backups",
                                    "mountPath": "/backups",
                                },
                            ],
                        },
                        # SFTP sidecar container (receives backups from cPanel)
                        sftp_container,
                    ],
                    "volumes": [
                        {
                            "name": "temp",
                            "emptyDir": {
                                "sizeLimit": "50Gi",
                            },
                        },
                        {
                            "name": "kubepanel",
                            "persistentVolumeClaim": {
                                "claimName": "kubepanel",
                            },
                        },
                        {
                            "name": "sftp-backups",
                            "persistentVolumeClaim": {
                                "claimName": sftp_pvc_name,
                            },
                        },
                    ],
                },
            },
        },
    }

    try:
        batch_v1.create_namespaced_job(
            namespace=MIGRATION_NAMESPACE,
            body=job_spec
        )
        logger.info(f"Created migration job: {job_name}")
        return job_name
    except ApiException as e:
        logger.error(f"Failed to create migration job: {e}")
        raise


def get_migration_job_status(job_name: str) -> dict:
    """
    Get the status of a migration job.

    Args:
        job_name: The K8s Job name

    Returns:
        Dict with status information:
        - active: Number of active pods
        - succeeded: Number of succeeded pods
        - failed: Number of failed pods
        - status: 'running', 'succeeded', 'failed', or 'unknown'
    """
    _load_k8s_config()
    batch_v1 = client.BatchV1Api()

    try:
        job = batch_v1.read_namespaced_job(
            name=job_name,
            namespace=MIGRATION_NAMESPACE
        )

        status = job.status
        result = {
            'active': status.active or 0,
            'succeeded': status.succeeded or 0,
            'failed': status.failed or 0,
        }

        if status.succeeded and status.succeeded > 0:
            result['status'] = 'succeeded'
        elif status.failed and status.failed > 0:
            result['status'] = 'failed'
        elif status.active and status.active > 0:
            result['status'] = 'running'
        else:
            result['status'] = 'unknown'

        return result

    except ApiException as e:
        if e.status == 404:
            return {'status': 'not_found', 'active': 0, 'succeeded': 0, 'failed': 0}
        raise


def delete_migration_job(job_name: str, propagation_policy: str = 'Foreground'):
    """
    Delete a migration job and its pods.

    Args:
        job_name: The K8s Job name
        propagation_policy: 'Foreground' or 'Background'
    """
    _load_k8s_config()
    batch_v1 = client.BatchV1Api()

    try:
        batch_v1.delete_namespaced_job(
            name=job_name,
            namespace=MIGRATION_NAMESPACE,
            body=client.V1DeleteOptions(
                propagation_policy=propagation_policy
            )
        )
        logger.info(f"Deleted migration job: {job_name}")
    except ApiException as e:
        if e.status != 404:
            logger.error(f"Failed to delete migration job: {e}")
            raise


def get_migration_job_logs(job_name: str, tail_lines: int = 100, container: str = 'migrator') -> Optional[str]:
    """
    Get logs from a migration job's pod.

    Args:
        job_name: The K8s Job name
        tail_lines: Number of lines to retrieve
        container: Container name ('migrator' or 'sftp')

    Returns:
        Log content or None if not available
    """
    _load_k8s_config()
    core_v1 = client.CoreV1Api()

    try:
        # Find the pod for this job
        pods = core_v1.list_namespaced_pod(
            namespace=MIGRATION_NAMESPACE,
            label_selector=f"job-name={job_name}"
        )

        if not pods.items:
            return None

        pod = pods.items[0]
        logs = core_v1.read_namespaced_pod_log(
            name=pod.metadata.name,
            namespace=MIGRATION_NAMESPACE,
            container=container,
            tail_lines=tail_lines,
        )
        return logs

    except ApiException as e:
        logger.error(f"Failed to get job logs: {e}")
        return None
