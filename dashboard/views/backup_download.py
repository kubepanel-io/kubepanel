"""
Backup Download Views

Provides portable backup downloads in tar.gz format.
"""

import json
import logging
import subprocess
import time
import uuid

from django.http import StreamingHttpResponse, HttpResponseNotFound, JsonResponse
from django.views import View
from django.core.exceptions import PermissionDenied
from kubernetes import client, config
from kubernetes.client import ApiException

from dashboard.models import Domain
from dashboard.k8s import get_backup

logger = logging.getLogger(__name__)

# Storage class for temporary PVCs
STORAGE_CLASS = 'linstor-sc'


def _load_k8s_config():
    """Load Kubernetes configuration."""
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()


def _get_namespace_from_backup_name(backup_name: str) -> str:
    """
    Extract namespace from backup name.

    Backup name format: domain-name-YYYYMMDD-HHMMSS
    e.g., example-com-20240115-020000 -> dom-example-com
    """
    parts = backup_name.rsplit('-', 2)
    if len(parts) < 3:
        raise ValueError(f"Invalid backup name format: {backup_name}")
    domain_slug = parts[0]
    return f"dom-{domain_slug}"


def _create_temp_pvc_from_snapshot(
    namespace: str,
    snapshot_name: str,
    pvc_name: str,
    storage_size: str = "10Gi"
) -> None:
    """
    Create a temporary PVC from a VolumeSnapshot.

    Note: With WaitForFirstConsumer storage classes (like Linstor),
    the PVC will stay Pending until a Pod mounts it. We don't wait
    for binding here - the Job creation will trigger binding.
    """
    _load_k8s_config()
    v1 = client.CoreV1Api()

    pvc_body = {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": pvc_name,
            "namespace": namespace,
        },
        "spec": {
            "storageClassName": STORAGE_CLASS,
            "resources": {
                "requests": {
                    "storage": storage_size
                }
            },
            "dataSource": {
                "apiGroup": "snapshot.storage.k8s.io",
                "kind": "VolumeSnapshot",
                "name": snapshot_name
            },
            "accessModes": ["ReadWriteOnce"]
        }
    }

    v1.create_namespaced_persistent_volume_claim(
        namespace=namespace,
        body=pvc_body
    )
    logger.info(f"Created temp PVC {pvc_name} from snapshot {snapshot_name}")


def _delete_temp_pvc(namespace: str, pvc_name: str) -> None:
    """Delete a temporary PVC."""
    _load_k8s_config()
    v1 = client.CoreV1Api()

    try:
        v1.delete_namespaced_persistent_volume_claim(
            name=pvc_name,
            namespace=namespace,
            body=client.V1DeleteOptions(propagation_policy='Foreground')
        )
    except ApiException as e:
        if e.status != 404:
            logger.error(f"Failed to delete PVC {pvc_name}: {e}")


def _create_download_job(
    namespace: str,
    job_name: str,
    data_pvc_name: str,
    backup_pvc_name: str = "backup"
) -> str:
    """
    Create a Job for downloading backup data.

    Returns the name of the pod created by the job.

    Note: The job's pod will trigger PVC binding for WaitForFirstConsumer
    storage classes. This may take extra time for snapshot restoration.
    """
    _load_k8s_config()
    batch_v1 = client.BatchV1Api()
    core_v1 = client.CoreV1Api()

    job_body = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": job_name,
            "namespace": namespace,
        },
        "spec": {
            "ttlSecondsAfterFinished": 60,
            "template": {
                "spec": {
                    "restartPolicy": "Never",
                    "volumes": [
                        {
                            "name": "data-pvc",
                            "persistentVolumeClaim": {"claimName": data_pvc_name}
                        },
                        {
                            "name": "backup-pvc",
                            "persistentVolumeClaim": {"claimName": backup_pvc_name}
                        }
                    ],
                    "containers": [{
                        "name": "archiver",
                        "image": "alpine:latest",
                        "command": ["sh", "-c", "apk add --no-cache zstd && sleep 3600"],
                        "volumeMounts": [
                            {"mountPath": "/data", "name": "data-pvc", "readOnly": True},
                            {"mountPath": "/backup", "name": "backup-pvc", "readOnly": True}
                        ]
                    }]
                }
            }
        }
    }

    batch_v1.create_namespaced_job(namespace=namespace, body=job_body)
    logger.info(f"Created download job {job_name}")

    # Wait for pod to be running (includes time for PVC binding with WaitForFirstConsumer)
    pod_name = None
    for i in range(180):  # 3 minute timeout (PVC binding + snapshot restore can be slow)
        pods = core_v1.list_namespaced_pod(
            namespace=namespace,
            label_selector=f"job-name={job_name}"
        ).items
        if pods:
            pod = pods[0]
            pod_name = pod.metadata.name
            phase = pod.status.phase
            if phase == "Running":
                logger.info(f"Job pod {pod_name} is running")
                return pod_name
            elif phase == "Failed":
                raise RuntimeError(f"Job pod {pod_name} failed")
            # Log progress every 10 seconds
            if i > 0 and i % 10 == 0:
                logger.info(f"Waiting for job pod {pod_name}, phase: {phase}")
        time.sleep(1)

    raise TimeoutError(f"Job pod did not start within timeout (3 minutes)")


def _create_sql_download_job(
    namespace: str,
    job_name: str,
    backup_pvc_name: str = "backup"
) -> str:
    """
    Create a Job for downloading SQL backup only.

    Returns the name of the pod created by the job.
    """
    _load_k8s_config()
    batch_v1 = client.BatchV1Api()
    core_v1 = client.CoreV1Api()

    job_body = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": job_name,
            "namespace": namespace,
        },
        "spec": {
            "ttlSecondsAfterFinished": 60,
            "template": {
                "spec": {
                    "restartPolicy": "Never",
                    "volumes": [
                        {
                            "name": "backup-pvc",
                            "persistentVolumeClaim": {"claimName": backup_pvc_name}
                        }
                    ],
                    "containers": [{
                        "name": "downloader",
                        "image": "alpine:latest",
                        "command": ["sh", "-c", "apk add --no-cache zstd gzip && sleep 3600"],
                        "volumeMounts": [
                            {"mountPath": "/backup", "name": "backup-pvc", "readOnly": True}
                        ]
                    }]
                }
            }
        }
    }

    batch_v1.create_namespaced_job(namespace=namespace, body=job_body)

    # Wait for pod to be running
    pod_name = None
    for _ in range(120):
        pods = core_v1.list_namespaced_pod(
            namespace=namespace,
            label_selector=f"job-name={job_name}"
        ).items
        if pods:
            pod = pods[0]
            pod_name = pod.metadata.name
            if pod.status.phase == "Running":
                return pod_name
        time.sleep(1)

    raise TimeoutError(f"Job pod did not start within timeout")


def _cleanup_job(namespace: str, job_name: str) -> None:
    """Delete a job and its pods."""
    _load_k8s_config()
    batch_v1 = client.BatchV1Api()

    try:
        batch_v1.delete_namespaced_job(
            name=job_name,
            namespace=namespace,
            body=client.V1DeleteOptions(propagation_policy='Foreground')
        )
    except ApiException as e:
        if e.status != 404:
            logger.error(f"Failed to delete job {job_name}: {e}")


class DownloadBackupArchiveView(View):
    """
    Download a complete backup as a portable tar.gz archive.

    The archive contains:
    - html/ - Site files
    - database.sql - Decompressed MariaDB dump
    - manifest.json - Metadata about the backup
    """

    def get(self, request, backup_name):
        logger.info(f"Archive download requested for backup: {backup_name}")

        # Parse backup name to get namespace
        try:
            namespace = _get_namespace_from_backup_name(backup_name)
            logger.info(f"Parsed namespace: {namespace}")
        except ValueError as e:
            logger.error(f"Invalid backup name format: {backup_name} - {e}")
            return HttpResponseNotFound("Invalid backup name format")

        # Get backup from Kubernetes
        backup = get_backup(namespace, backup_name)
        if not backup:
            logger.error(f"Backup {backup_name} not found in namespace {namespace}")
            return HttpResponseNotFound(f"Backup {backup_name} not found")

        logger.info(f"Found backup: {backup.name}, phase: {backup.status.phase}")
        logger.info(f"Backup status - volume_snapshot_name: {backup.status.volume_snapshot_name}, db_path: {backup.status.database_backup_path}")

        # Check if backup is completed
        if backup.status.phase != 'Completed':
            logger.error(f"Backup {backup_name} is not completed, phase: {backup.status.phase}")
            return HttpResponseNotFound("Backup is not completed yet")

        # Check permissions
        domain_name = backup.domain_name
        try:
            domain = Domain.objects.get(domain_name=domain_name)
            if not request.user.is_superuser and domain.owner != request.user:
                logger.error(f"Permission denied for user {request.user} on domain {domain_name}")
                raise PermissionDenied
        except Domain.DoesNotExist:
            logger.error(f"Domain {domain_name} not found in database")
            raise PermissionDenied

        # Check if backup has required data
        volume_snapshot_name = backup.status.volume_snapshot_name
        db_backup_path = backup.status.database_backup_path

        if not volume_snapshot_name:
            logger.error(f"Backup {backup_name} has no volume snapshot name. Status: {backup.status}")
            return HttpResponseNotFound("Backup does not have a volume snapshot. This backup may have been created before snapshot support was added.")

        # Generate unique names for temporary resources
        unique_id = str(uuid.uuid4())[:8]
        temp_pvc_name = f"download-{unique_id}"
        job_name = f"download-archive-{unique_id}"

        try:
            # Get domain's storage size for temp PVC
            storage_size = f"{domain.storage_size}Gi"

            # Create temporary PVC from snapshot
            _create_temp_pvc_from_snapshot(
                namespace=namespace,
                snapshot_name=volume_snapshot_name,
                pvc_name=temp_pvc_name,
                storage_size=storage_size
            )

            # Create the download job
            pod_name = _create_download_job(
                namespace=namespace,
                job_name=job_name,
                data_pvc_name=temp_pvc_name,
            )

            # Build manifest
            manifest = {
                "version": "1.0",
                "domain": domain_name,
                "backup_name": backup_name,
                "created_at": backup.created_at,
            }
            manifest_json = json.dumps(manifest, indent=2)

            # Build the tar command:
            # 1. Create manifest
            # 2. Tar html directory from /data/html
            # 3. Include database.sql (decompressed from zstd)
            # DEBUG: Added sleep and ls for inspection
            tar_cmd = f"""
                echo "=== DEBUG: Listing /data ===" && \
                ls -la /data/ && \
                echo "=== DEBUG: Listing /backup ===" && \
                ls -la /backup/ && \
                echo "=== DEBUG: db_backup_path = {db_backup_path} ===" && \
                cd /tmp && \
                echo '{manifest_json}' > manifest.json && \
                cp -a /data/html . 2>/dev/null || mkdir -p html && \
                zstd -d {db_backup_path} -o database.sql 2>/dev/null || echo "" > database.sql && \
                tar czf - manifest.json html database.sql && \
                sleep 300
            """

            logger.info(f"DEBUG: Pod for inspection: kubectl exec -it -n {namespace} {pod_name} -c archiver -- sh")

            cmd = [
                "kubectl", "exec", "-i",
                "-n", namespace,
                pod_name, "-c", "archiver",
                "--", "sh", "-c", tar_cmd
            ]

            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            def stream_generator():
                try:
                    for chunk in iter(lambda: proc.stdout.read(64 * 1024), b""):
                        yield chunk
                    code = proc.wait()
                    if code != 0:
                        err = proc.stderr.read().decode(errors="ignore")
                        logger.error(f"Archive download failed: {err}")
                finally:
                    # DEBUG: Disabled cleanup for inspection
                    # _cleanup_job(namespace, job_name)
                    # _delete_temp_pvc(namespace, temp_pvc_name)
                    logger.info(f"DEBUG: Skipping cleanup. Inspect with: kubectl exec -it -n {namespace} {pod_name} -c archiver -- sh")
                    logger.info(f"DEBUG: Cleanup manually: kubectl delete job {job_name} -n {namespace} && kubectl delete pvc {temp_pvc_name} -n {namespace}")

            response = StreamingHttpResponse(
                stream_generator(),
                content_type="application/gzip"
            )
            response["Content-Disposition"] = f'attachment; filename="{backup_name}.tar.gz"'
            return response

        except TimeoutError as e:
            # DEBUG: Disabled cleanup for inspection
            logger.error(f"TimeoutError in archive download: {e}")
            logger.info(f"DEBUG: Cleanup manually: kubectl delete job {job_name} -n {namespace} && kubectl delete pvc {temp_pvc_name} -n {namespace}")
            return HttpResponseNotFound(str(e))
        except ApiException as e:
            # DEBUG: Disabled cleanup for inspection
            logger.error(f"ApiException in archive download: {e}")
            logger.info(f"DEBUG: Cleanup manually: kubectl delete job {job_name} -n {namespace} && kubectl delete pvc {temp_pvc_name} -n {namespace}")
            return HttpResponseNotFound(f"Kubernetes API error: {e.reason}")
        except Exception as e:
            # DEBUG: Disabled cleanup for inspection
            logger.exception(f"Unexpected error in archive download for {backup_name}: {e}")
            logger.info(f"DEBUG: Cleanup manually: kubectl delete job {job_name} -n {namespace} && kubectl delete pvc {temp_pvc_name} -n {namespace}")
            return HttpResponseNotFound(f"Error: {e}")


class DownloadBackupSqlView(View):
    """
    Download just the SQL dump from a backup as .sql.gz.

    Decompresses the zstd backup and recompresses as gzip for portability.
    """

    def get(self, request, backup_name):
        # Parse backup name to get namespace
        try:
            namespace = _get_namespace_from_backup_name(backup_name)
        except ValueError:
            return HttpResponseNotFound("Invalid backup name format")

        # Get backup from Kubernetes
        backup = get_backup(namespace, backup_name)
        if not backup:
            return HttpResponseNotFound(f"Backup {backup_name} not found")

        # Check if backup is completed
        if backup.status.phase != 'Completed':
            return HttpResponseNotFound("Backup is not completed yet")

        # Check permissions
        domain_name = backup.domain_name
        try:
            domain = Domain.objects.get(domain_name=domain_name)
            if not request.user.is_superuser and domain.owner != request.user:
                raise PermissionDenied
        except Domain.DoesNotExist:
            raise PermissionDenied

        # Check if backup has database
        db_backup_path = backup.status.database_backup_path
        if not db_backup_path:
            return HttpResponseNotFound("Backup does not have a database dump")

        # Generate unique names
        unique_id = str(uuid.uuid4())[:8]
        job_name = f"download-sql-{unique_id}"

        try:
            # Create the download job (just backup PVC)
            pod_name = _create_sql_download_job(
                namespace=namespace,
                job_name=job_name,
            )

            # Decompress zstd and recompress as gzip
            cmd = [
                "kubectl", "exec", "-i",
                "-n", namespace,
                pod_name, "-c", "downloader",
                "--", "sh", "-c",
                f"zstd -d {db_backup_path} -c | gzip"
            ]

            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            def stream_generator():
                try:
                    for chunk in iter(lambda: proc.stdout.read(64 * 1024), b""):
                        yield chunk
                    code = proc.wait()
                    if code != 0:
                        err = proc.stderr.read().decode(errors="ignore")
                        logger.error(f"SQL download failed: {err}")
                finally:
                    _cleanup_job(namespace, job_name)

            response = StreamingHttpResponse(
                stream_generator(),
                content_type="application/gzip"
            )
            response["Content-Disposition"] = f'attachment; filename="{backup_name}.sql.gz"'
            return response

        except TimeoutError as e:
            _cleanup_job(namespace, job_name)
            return HttpResponseNotFound(str(e))
        except ApiException as e:
            _cleanup_job(namespace, job_name)
            return HttpResponseNotFound(f"Kubernetes API error: {e.reason}")


# Function-based views for URL routing
from django.contrib.auth.decorators import login_required


@login_required
def download_backup_archive(request, backup_name):
    """Download complete backup archive."""
    return DownloadBackupArchiveView.as_view()(request, backup_name=backup_name)


@login_required
def download_backup_sql(request, backup_name):
    """Download SQL dump only."""
    return DownloadBackupSqlView.as_view()(request, backup_name=backup_name)
