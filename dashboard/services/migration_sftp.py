"""
Migration SFTP Service

Creates temporary SFTP infrastructure for receiving cPanel backups.
Each migration batch gets its own PVC, Secret, and Service.
The SFTP server runs as a sidecar in the migration worker Job.
"""

import json
import logging
import secrets
import string
import urllib.request

from kubernetes import client, config
from kubernetes.client import ApiException

logger = logging.getLogger(__name__)

NAMESPACE = 'kubepanel'
LINSTOR_API_URL = "http://linstor-controller.piraeus-datastore.svc.cluster.local:3370"


def get_linstor_min_free_capacity_gb() -> int:
    """
    Query Linstor API for minimum free capacity across all storage pools.

    Returns the minimum free capacity in GB across all non-DISKLESS pools.
    This ensures the PVC can be placed on any node.

    Returns:
        Minimum free capacity in GB, or 9 as fallback if API fails.
    """
    try:
        api_url = f"{LINSTOR_API_URL}/v1/view/storage-pools"
        logger.info(f"Querying Linstor API: {api_url}")
        req = urllib.request.Request(api_url, headers={'Accept': 'application/json'})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))

        logger.info(f"Linstor returned {len(data)} storage pools")

        # Find minimum free capacity across non-DISKLESS pools
        min_free_kib = None
        pool_count = 0
        for pool in data:
            provider_kind = pool.get('provider_kind', '')
            if provider_kind == 'DISKLESS':
                continue

            pool_count += 1
            node_name = pool.get('node_name', 'unknown')
            free_capacity_kib = pool.get('free_capacity', 0)
            logger.info(f"Pool on {node_name}: {free_capacity_kib} KiB free ({provider_kind})")

            if min_free_kib is None or free_capacity_kib < min_free_kib:
                min_free_kib = free_capacity_kib

        if min_free_kib is None or pool_count == 0:
            logger.warning(f"No non-DISKLESS storage pools found (total pools: {len(data)}), using default 9Gi")
            return 9

        # Convert KiB to GiB (1 GiB = 1024*1024 KiB)
        min_free_gib = int(min_free_kib / (1024 * 1024))
        logger.info(f"Linstor minimum free capacity: {min_free_gib}Gi across {pool_count} pools")

        # Cap at reasonable maximum, allow small values
        return min(min_free_gib, 2000) if min_free_gib > 0 else 9

    except Exception as e:
        logger.error(f"Failed to query Linstor API: {e}")
        return 9  # Fallback to 9Gi


def _load_k8s_config():
    """Load Kubernetes configuration."""
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()


def generate_password(length=24):
    """Generate a secure random password."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def create_migration_sftp(batch_id: int, storage_class: str = 'linstor-sc') -> dict:
    """
    Create SFTP infrastructure for a migration batch.

    Creates:
    - Secret with credentials
    - PVC for backup storage (sized based on Linstor free capacity)
    - NodePort Service for external access

    The SFTP server itself runs as a sidecar in the migration worker Job.

    Args:
        batch_id: The migration batch ID
        storage_class: Kubernetes storage class for the PVC

    Returns:
        dict with 'username', 'password', 'port', 'pvc_name', 'secret_name', 'storage_size'
    """
    _load_k8s_config()

    name = f"migration-sftp-{batch_id}"
    password = generate_password()
    username = "migration"

    core_v1 = client.CoreV1Api()

    labels = {
        "app": "migration-sftp",
        "batch-id": str(batch_id),
    }

    # 1. Create Secret with credentials
    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(
            name=name,
            namespace=NAMESPACE,
            labels=labels,
        ),
        string_data={
            "username": username,
            "password": password,
        },
    )
    core_v1.create_namespaced_secret(NAMESPACE, secret)
    logger.info(f"Created secret {name}")

    # 2. Get storage size from Linstor (minimum free capacity)
    storage_size_gb = get_linstor_min_free_capacity_gb()
    storage_size = f"{storage_size_gb}Gi"
    logger.info(f"Using storage size: {storage_size}")

    # 3. Create PVC for backups
    pvc = client.V1PersistentVolumeClaim(
        metadata=client.V1ObjectMeta(
            name=name,
            namespace=NAMESPACE,
            labels=labels,
        ),
        spec=client.V1PersistentVolumeClaimSpec(
            access_modes=["ReadWriteOnce"],
            storage_class_name=storage_class,
            resources=client.V1ResourceRequirements(
                requests={"storage": storage_size},
            ),
        ),
    )
    core_v1.create_namespaced_persistent_volume_claim(NAMESPACE, pvc)
    logger.info(f"Created PVC {name} with size {storage_size}")

    # 4. Create NodePort Service for SSH/SCP access
    # The service selector will match the migration job pod (which includes SSH sidecar)
    # linuxserver/openssh-server uses port 2222 by default
    service = client.V1Service(
        metadata=client.V1ObjectMeta(
            name=name,
            namespace=NAMESPACE,
            labels=labels,
        ),
        spec=client.V1ServiceSpec(
            type="NodePort",
            selector={
                "app": "cpanel-migration",
                "batch-id": str(batch_id),
            },
            ports=[
                client.V1ServicePort(port=22, target_port=2222),
            ],
        ),
    )
    created_service = core_v1.create_namespaced_service(NAMESPACE, service)
    logger.info(f"Created service {name}")

    # Get the assigned NodePort
    node_port = created_service.spec.ports[0].node_port

    logger.info(f"Created migration SSH/SCP infrastructure for batch {batch_id} on port {node_port}")

    return {
        "username": username,
        "password": password,
        "port": node_port,
        "pvc_name": name,
        "secret_name": name,
        "storage_size": storage_size,
    }


def delete_migration_sftp(batch_id: int):
    """
    Clean up SSH/SCP infrastructure for a migration batch.

    Removes the Service, PVC, and Secret.

    Args:
        batch_id: The migration batch ID
    """
    _load_k8s_config()

    name = f"migration-sftp-{batch_id}"
    core_v1 = client.CoreV1Api()

    # Delete in reverse order of creation
    try:
        core_v1.delete_namespaced_service(name, NAMESPACE)
        logger.info(f"Deleted service {name}")
    except ApiException as e:
        if e.status != 404:
            logger.warning(f"Failed to delete service {name}: {e}")

    try:
        core_v1.delete_namespaced_persistent_volume_claim(name, NAMESPACE)
        logger.info(f"Deleted PVC {name}")
    except ApiException as e:
        if e.status != 404:
            logger.warning(f"Failed to delete PVC {name}: {e}")

    try:
        core_v1.delete_namespaced_secret(name, NAMESPACE)
        logger.info(f"Deleted secret {name}")
    except ApiException as e:
        if e.status != 404:
            logger.warning(f"Failed to delete secret {name}: {e}")

    logger.info(f"Cleaned up migration SFTP for batch {batch_id}")


def get_sftp_container_spec(batch_id: int, username: str, password: str) -> dict:
    """
    Get the SCP/SFTP sidecar container specification for the migration Job.

    Uses linuxserver/openssh-server which supports both SCP and SFTP.
    cPanel uses SCP (not SFTP) for fullbackup_to_scp_with_password.

    Args:
        batch_id: The migration batch ID
        username: SSH username
        password: SSH password

    Returns:
        Container spec dict for the SSH sidecar
    """
    return {
        "name": "sftp",
        "image": "linuxserver/openssh-server:latest",
        "ports": [{"containerPort": 2222}],
        "env": [
            {"name": "PUID", "value": "1000"},
            {"name": "PGID", "value": "1000"},
            {"name": "TZ", "value": "UTC"},
            {"name": "USER_NAME", "value": username},
            {"name": "USER_PASSWORD", "value": password},
            {"name": "PASSWORD_ACCESS", "value": "true"},
            {"name": "SUDO_ACCESS", "value": "false"},
        ],
        "volumeMounts": [
            {
                # Mount PVC at /data - a neutral location for uploads
                # We'll set the SCP directory to /data/{username}
                "name": "sftp-backups",
                "mountPath": "/data",
            },
        ],
        "resources": {
            "requests": {
                "memory": "64Mi",
                "cpu": "50m",
            },
            "limits": {
                "memory": "256Mi",
                "cpu": "500m",
            },
        },
    }
