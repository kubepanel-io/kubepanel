"""
Storage views for displaying Linstor volume placement by domain.
"""
import logging
import urllib.request
import json

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from kubernetes import client

from dashboard.models import Domain
from dashboard.views.utils import _load_k8s_auth

logger = logging.getLogger(__name__)

LINSTOR_API_URL = "http://linstor-controller.piraeus-datastore.svc.cluster.local:3370"


@login_required
def storage_list(request):
    """Display Linstor volumes mapped to domains."""
    if not request.user.is_superuser:
        return redirect('kpmain')

    error_message = None

    # 1. Get Linstor resources
    linstor_resources, linstor_error = get_linstor_resources()
    if linstor_error:
        error_message = linstor_error

    # 2. Get PV -> PVC mappings
    pv_mappings, pv_error = get_pv_mappings()
    if pv_error:
        error_message = error_message or pv_error

    # 3. Build domain-grouped data
    storage_data = build_storage_data(linstor_resources, pv_mappings)

    return render(request, 'main/storage_list.html', {
        'storage_data': storage_data,
        'error_message': error_message,
    })


def get_linstor_resources():
    """Fetch resources from Linstor REST API."""
    try:
        api_url = f"{LINSTOR_API_URL}/v1/view/resources"
        req = urllib.request.Request(api_url, headers={'Accept': 'application/json'})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
        return data, None
    except urllib.error.URLError as e:
        logger.error(f"Failed to reach Linstor API: {e}")
        return [], f"Cannot reach Linstor API: {e.reason}"
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON from Linstor API: {e}")
        return [], f"Invalid response from Linstor API"
    except Exception as e:
        logger.error(f"Failed to fetch Linstor resources: {e}")
        return [], f"Failed to fetch Linstor resources: {e}"


def get_pv_mappings():
    """Get PV to PVC/namespace mappings from Kubernetes."""
    mappings = {}  # resource_name -> {pv_name, pvc_name, namespace, capacity}

    try:
        _load_k8s_auth()
        v1 = client.CoreV1Api()

        pvs = v1.list_persistent_volume()
        for pv in pvs.items:
            # Only process Linstor CSI volumes
            if not pv.spec.csi:
                continue
            if pv.spec.csi.driver != "linstor.csi.linbit.com":
                continue

            resource_name = pv.spec.csi.volume_handle
            claim_ref = pv.spec.claim_ref

            if claim_ref:
                capacity = pv.spec.capacity.get('storage', 'Unknown') if pv.spec.capacity else 'Unknown'
                mappings[resource_name] = {
                    'pv_name': pv.metadata.name,
                    'pvc_name': claim_ref.name,
                    'namespace': claim_ref.namespace,
                    'capacity': capacity,
                }

        return mappings, None
    except Exception as e:
        logger.error(f"Failed to list PVs: {e}")
        return {}, f"Failed to list Kubernetes PVs: {e}"


def build_storage_data(linstor_resources, pv_mappings):
    """Combine Linstor and K8s data, grouped by domain."""
    # Build namespace -> domain lookup
    domains = {d.namespace: d for d in Domain.objects.all()}

    # Group by domain
    domain_storage = {}  # domain_name -> {domain: Domain, volumes: []}

    for resource in linstor_resources:
        resource_name = resource.get('name', '')

        # Get PV mapping
        pv_info = pv_mappings.get(resource_name, {})
        namespace = pv_info.get('namespace', '')

        # Find domain
        domain = domains.get(namespace)
        if domain:
            domain_name = domain.domain_name
        elif namespace:
            domain_name = namespace  # Show namespace if no domain match
        else:
            domain_name = 'Unknown'

        # Extract node info from resource
        node_name = resource.get('node_name', 'Unknown')

        # Get volume state and size
        volumes = resource.get('volumes', [])
        state = 'Unknown'
        size_kib = 0
        for vol in volumes:
            state_info = vol.get('state', {})
            state = state_info.get('disk_state', 'Unknown')
            size_kib = vol.get('allocated_size_kib', 0)

        # Build entry
        entry = {
            'resource_name': resource_name,
            'pvc_name': pv_info.get('pvc_name', 'N/A'),
            'pv_name': pv_info.get('pv_name', 'N/A'),
            'size': pv_info.get('capacity', format_size_kib(size_kib)),
            'node': node_name,
            'state': state,
        }

        if domain_name not in domain_storage:
            domain_storage[domain_name] = {
                'domain': domain,
                'volumes': [],
            }
        domain_storage[domain_name]['volumes'].append(entry)

    # Sort by domain name
    return dict(sorted(domain_storage.items()))


def format_size_kib(size_kib):
    """Format size in KiB to human-readable format."""
    if size_kib == 0:
        return 'N/A'

    size_gib = size_kib / (1024 * 1024)
    if size_gib >= 1:
        return f"{size_gib:.1f}Gi"

    size_mib = size_kib / 1024
    return f"{size_mib:.0f}Mi"
