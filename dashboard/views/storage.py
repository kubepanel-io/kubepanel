"""
Storage views for displaying Linstor volume placement by domain.
"""
import logging
import urllib.request
import json

import requests
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required

from dashboard.models import Domain
from dashboard.views.utils import _load_k8s_auth

logger = logging.getLogger(__name__)

LINSTOR_API_URL = "http://linstor-controller.piraeus-datastore.svc.cluster.local:3370"


def fetch_linstor_storage_pools():
    """Fetch storage pool information from Linstor REST API."""
    try:
        api_url = f"{LINSTOR_API_URL}/v1/storage-pools"
        req = urllib.request.Request(api_url, headers={'Accept': 'application/json'})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
        return data, None
    except urllib.error.URLError as e:
        logger.error(f"Failed to reach Linstor storage pools API: {e}")
        return [], f"Cannot reach Linstor storage pools API: {e.reason}"
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON from Linstor storage pools API: {e}")
        return [], "Invalid response from Linstor storage pools API"
    except Exception as e:
        logger.error(f"Failed to fetch Linstor storage pools: {e}")
        return [], f"Failed to fetch Linstor storage pools: {e}"


def build_storage_pool_data(storage_pools):
    """
    Process storage pool data for display.

    Filters to LVM_THIN pools and calculates usage percentages.
    """
    pool_data = []

    for pool in storage_pools:
        provider_kind = pool.get('provider_kind', '')

        # Skip DISKLESS pools - they don't have actual storage
        if provider_kind == 'DISKLESS':
            continue

        node_name = pool.get('node_name', 'Unknown')
        pool_name = pool.get('storage_pool_name', 'Unknown')

        # Capacities are in KiB
        free_capacity_kib = pool.get('free_capacity', 0)
        total_capacity_kib = pool.get('total_capacity', 0)

        # Calculate used capacity
        used_capacity_kib = total_capacity_kib - free_capacity_kib

        # Calculate percentage
        if total_capacity_kib > 0:
            usage_percent = (used_capacity_kib / total_capacity_kib) * 100
        else:
            usage_percent = 0

        # Get pool path from props if available
        props = pool.get('props', {})
        pool_path = props.get('StorDriver/LvmVg', '')
        if not pool_path:
            pool_path = props.get('StorDriver/ThinPool', '')

        pool_data.append({
            'node_name': node_name,
            'pool_name': pool_name,
            'provider_kind': provider_kind,
            'pool_path': pool_path,
            'used_capacity': format_size_kib(used_capacity_kib),
            'total_capacity': format_size_kib(total_capacity_kib),
            'free_capacity': format_size_kib(free_capacity_kib),
            'usage_percent': round(usage_percent, 1),
            'used_kib': used_capacity_kib,
            'total_kib': total_capacity_kib,
        })

    # Sort by node name
    pool_data.sort(key=lambda x: x['node_name'])

    return pool_data


@login_required
def storage_list(request):
    """Display Linstor volumes mapped to domains."""
    if not request.user.is_superuser:
        return redirect('kpmain')

    errors = []

    # 1. Get Linstor storage pools (for overall capacity)
    storage_pools_raw, pools_error = fetch_linstor_storage_pools()
    if pools_error:
        errors.append(pools_error)
    storage_pools = build_storage_pool_data(storage_pools_raw)

    # 2. Get Linstor resources (single API call)
    linstor_resources, linstor_error = fetch_linstor_resources()
    if linstor_error:
        errors.append(linstor_error)

    # 3. Get all PVs from Kubernetes (single API call)
    pv_list, pv_error = fetch_all_pvs()
    if pv_error:
        errors.append(pv_error)

    # 4. Get all domains from Django (single query)
    domains = list(Domain.objects.all())

    # 5. Build domain-grouped storage data (consolidated by PVC)
    storage_data = build_storage_data(linstor_resources, pv_list, domains)

    # Calculate total storage pool stats
    total_used_kib = sum(p['used_kib'] for p in storage_pools)
    total_capacity_kib = sum(p['total_kib'] for p in storage_pools)
    total_usage_percent = round((total_used_kib / total_capacity_kib * 100), 1) if total_capacity_kib > 0 else 0

    return render(request, 'main/storage_list.html', {
        'storage_data': storage_data,
        'storage_pools': storage_pools,
        'total_pool_used': format_size_kib(total_used_kib),
        'total_pool_capacity': format_size_kib(total_capacity_kib),
        'total_pool_usage_percent': total_usage_percent,
        'error_message': '; '.join(errors) if errors else None,
    })


def fetch_linstor_resources():
    """Fetch all resources from Linstor REST API in one call."""
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
        return [], "Invalid response from Linstor API"
    except Exception as e:
        logger.error(f"Failed to fetch Linstor resources: {e}")
        return [], f"Failed to fetch Linstor resources: {e}"


def fetch_all_pvs():
    """Fetch all PersistentVolumes from Kubernetes API in one call."""
    try:
        base, headers, verify = _load_k8s_auth()
        resp = requests.get(
            f"{base}/api/v1/persistentvolumes",
            headers=headers,
            verify=verify,
            timeout=10
        )
        resp.raise_for_status()
        return resp.json().get('items', []), None
    except Exception as e:
        logger.error(f"Failed to list PVs: {e}")
        return [], f"Failed to list Kubernetes PVs: {e}"


def build_storage_data(linstor_resources, pv_list, domains):
    """
    Combine Linstor, K8s PV, and Domain data - consolidated by PVC.

    Since Linstor replicates volumes across nodes, we get multiple entries
    per PVC. This function consolidates them to show one row per PVC with
    all node placements listed together.
    """
    # Step 1: Build PV lookup (volume_handle -> PV info)
    pv_lookup = {}
    for pv in pv_list:
        spec = pv.get('spec', {})
        csi = spec.get('csi', {})

        if csi.get('driver') != 'linstor.csi.linbit.com':
            continue

        volume_handle = csi.get('volumeHandle', '')
        claim_ref = spec.get('claimRef', {})
        capacity = spec.get('capacity', {}).get('storage', 'Unknown')

        if volume_handle:
            pv_lookup[volume_handle] = {
                'pv_name': pv.get('metadata', {}).get('name', 'Unknown'),
                'pvc_name': claim_ref.get('name', 'N/A'),
                'namespace': claim_ref.get('namespace', ''),
                'capacity': capacity,
            }

    # Step 2: Build domain lookup (namespace -> domain)
    domain_lookup = {d.namespace: d for d in domains}

    # Step 3: Consolidate Linstor resources by resource_name (PVC)
    # resource_name -> {nodes: [{node, state}], pv_info, domain_name, domain}
    consolidated = {}

    for resource in linstor_resources:
        resource_name = resource.get('name', '')
        node_name = resource.get('node_name', 'Unknown')

        # Get resource-level state (includes in_use)
        resource_state = resource.get('state', {})
        in_use = resource_state.get('in_use', False)

        # Get volume state from Linstor
        volumes = resource.get('volumes', [])
        state = 'Unknown'
        size_kib = 0
        for vol in volumes:
            state_info = vol.get('state', {})
            state = state_info.get('disk_state', 'Unknown')
            size_kib = vol.get('allocated_size_kib', 0)

        # Look up PV info
        pv_info = pv_lookup.get(resource_name, {})
        namespace = pv_info.get('namespace', '')

        # Look up domain
        domain = domain_lookup.get(namespace)
        if domain:
            domain_name = domain.domain_name
        elif namespace:
            domain_name = namespace
        else:
            domain_name = 'System/Unknown'

        # Consolidate by resource_name
        if resource_name not in consolidated:
            consolidated[resource_name] = {
                'resource_name': resource_name,
                'pvc_name': pv_info.get('pvc_name', 'N/A'),
                'pv_name': pv_info.get('pv_name', 'N/A'),
                'size': pv_info.get('capacity') or format_size_kib(size_kib),
                'domain_name': domain_name,
                'domain': domain,
                'nodes': [],
            }

        # Add this node placement
        consolidated[resource_name]['nodes'].append({
            'name': node_name,
            'state': state,
            'in_use': in_use,
        })

    # Step 4: Group consolidated entries by domain
    domain_storage = {}

    for entry in consolidated.values():
        domain_name = entry['domain_name']

        # Calculate overall health
        nodes = entry['nodes']
        healthy_states = {'UpToDate', 'Diskless', 'TieBreaker'}
        healthy_count = sum(1 for n in nodes if n['state'] in healthy_states)
        total_count = len(nodes)

        # Determine overall status
        if healthy_count == total_count:
            overall_status = 'healthy'
        elif healthy_count > 0:
            overall_status = 'degraded'
        else:
            overall_status = 'error'

        volume_entry = {
            'resource_name': entry['resource_name'],
            'pvc_name': entry['pvc_name'],
            'pv_name': entry['pv_name'],
            'size': entry['size'],
            'nodes': sorted(nodes, key=lambda x: x['name']),
            'healthy_count': healthy_count,
            'total_count': total_count,
            'overall_status': overall_status,
        }

        if domain_name not in domain_storage:
            domain_storage[domain_name] = {
                'domain': entry['domain'],
                'volumes': [],
            }
        domain_storage[domain_name]['volumes'].append(volume_entry)

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
