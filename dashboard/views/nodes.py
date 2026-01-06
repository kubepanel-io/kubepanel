"""
Kubernetes node and pod management views
"""
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.contrib import messages

import os
import re
import requests
import logging

from dashboard.models import Domain, SystemHealthStatus, SystemSettings
from .utils import _load_k8s_auth

# Try to import kubernetes client for exec functionality
try:
    from kubernetes import client as k8s_client, config as k8s_config
    from kubernetes.stream import stream as k8s_stream
    K8S_CLIENT_AVAILABLE = True
except ImportError:
    K8S_CLIENT_AVAILABLE = False

logger = logging.getLogger("django")


def parse_cpu(cpu_str: str) -> int:
    """Parse CPU string to millicores (int).

    Examples:
        "500m" -> 500
        "2" -> 2000
        "100n" -> 0 (nanocores, too small)
    """
    if not cpu_str:
        return 0
    cpu_str = str(cpu_str).strip()
    if cpu_str.endswith('n'):
        # nanocores to millicores
        return int(cpu_str[:-1]) // 1_000_000
    elif cpu_str.endswith('m'):
        return int(cpu_str[:-1])
    else:
        # whole cores to millicores
        return int(float(cpu_str) * 1000)


def parse_memory(mem_str: str) -> int:
    """Parse memory string to bytes (int).

    Examples:
        "1Gi" -> 1073741824
        "512Mi" -> 536870912
        "1024Ki" -> 1048576
        "1000000" -> 1000000 (already bytes)
    """
    if not mem_str:
        return 0
    mem_str = str(mem_str).strip()

    suffixes = {
        'Ki': 1024,
        'Mi': 1024 ** 2,
        'Gi': 1024 ** 3,
        'Ti': 1024 ** 4,
        'K': 1000,
        'M': 1000 ** 2,
        'G': 1000 ** 3,
        'T': 1000 ** 4,
    }

    for suffix, multiplier in suffixes.items():
        if mem_str.endswith(suffix):
            return int(float(mem_str[:-len(suffix)]) * multiplier)

    return int(mem_str)


def format_memory_human(bytes_val: int) -> str:
    """Format bytes to human-readable string."""
    if bytes_val <= 0:
        return "0 B"

    for unit in ['B', 'Ki', 'Mi', 'Gi', 'Ti']:
        if bytes_val < 1024:
            if unit == 'B':
                return f"{bytes_val} {unit}"
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024

    return f"{bytes_val:.1f} Pi"


def get_node_stats_via_exec():
    """
    Get node stats (uptime, load average, disk usage) by exec'ing into
    nginx-ingress-controller pods running on each node.

    Returns a dict mapping node_name -> {uptime, load_avg, disk_usage, disk_percent}
    """
    if not K8S_CLIENT_AVAILABLE:
        logger.warning("kubernetes python client not available - install with: pip install kubernetes")
        return {}

    try:
        k8s_config.load_incluster_config()
        logger.debug("Loaded in-cluster k8s config for exec")
    except Exception as e1:
        try:
            k8s_config.load_kube_config()
            logger.debug("Loaded kube config file for exec")
        except Exception as e2:
            logger.warning(f"Failed to load k8s config for exec: in-cluster={e1}, kubeconfig={e2}")
            return {}

    v1 = k8s_client.CoreV1Api()
    node_stats = {}

    # Find nginx-ingress-controller pods (DaemonSet runs on all nodes)
    try:
        # Try different namespace/label combinations for various nginx-ingress installations
        search_configs = [
            # MicroK8s ingress addon
            {'namespace': 'ingress', 'label_selector': 'name=nginx-ingress-microk8s'},
            # Standard ingress-nginx
            {'namespace': 'ingress-nginx', 'label_selector': 'app.kubernetes.io/name=ingress-nginx'},
            {'namespace': 'ingress', 'label_selector': 'app.kubernetes.io/name=ingress-nginx'},
            {'namespace': 'kube-system', 'label_selector': 'app.kubernetes.io/name=ingress-nginx'},
        ]
        pods = []

        for config in search_configs:
            try:
                pod_list = v1.list_namespaced_pod(
                    namespace=config['namespace'],
                    label_selector=config['label_selector']
                )
                if pod_list.items:
                    pods = pod_list.items
                    logger.info(f"Found {len(pods)} nginx-ingress pods in {config['namespace']} with {config['label_selector']}")
                    break
            except Exception:
                continue

        if not pods:
            logger.warning("No nginx-ingress pods found for exec stats. Tried configs: %s", search_configs)
            return {}

        logger.info(f"Processing {len(pods)} nginx-ingress pods for exec stats")
        for pod in pods:
            if pod.status.phase != 'Running':
                continue

            node_name = pod.spec.node_name
            pod_name = pod.metadata.name
            namespace = pod.metadata.namespace

            try:
                # Get uptime and load average
                uptime_output = k8s_stream(
                    v1.connect_get_namespaced_pod_exec,
                    pod_name,
                    namespace,
                    command=['uptime'],
                    stderr=True,
                    stdin=False,
                    stdout=True,
                    tty=False
                )
                uptime_data = parse_uptime_output(uptime_output)

                # Get disk usage
                df_output = k8s_stream(
                    v1.connect_get_namespaced_pod_exec,
                    pod_name,
                    namespace,
                    command=['df', '-hT', '/'],
                    stderr=True,
                    stdin=False,
                    stdout=True,
                    tty=False
                )
                disk_data = parse_df_output(df_output)

                node_stats[node_name] = {
                    **uptime_data,
                    **disk_data,
                }

            except Exception as e:
                logger.error(f"Failed to exec into pod {pod_name} on node {node_name}: {type(e).__name__}: {e}")
                continue

    except Exception as e:
        logger.error(f"Failed to get node stats via exec: {type(e).__name__}: {e}")

    return node_stats


def parse_uptime_output(output: str) -> dict:
    """
    Parse uptime command output.

    Example outputs:
     16:42:01 up 45 days,  3:22,  0 users,  load average: 0.52, 0.58, 0.59
     16:42:01 up 2:30,  0 users,  load average: 1.00, 0.80, 0.75
     16:42:01 up 10 min,  0 users,  load average: 0.00, 0.01, 0.05
    """
    result = {
        'uptime': 'N/A',
        'load_1': 0.0,
        'load_5': 0.0,
        'load_15': 0.0,
        'load_avg': 'N/A',
    }

    if not output:
        return result

    output = output.strip()

    # Extract uptime part - between "up " and the first comma before "user"
    uptime_match = re.search(r'up\s+(.+?),\s*\d+\s*user', output)
    if uptime_match:
        result['uptime'] = uptime_match.group(1).strip()

    # Extract load averages
    load_match = re.search(r'load average[s]?:\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)', output)
    if load_match:
        result['load_1'] = float(load_match.group(1))
        result['load_5'] = float(load_match.group(2))
        result['load_15'] = float(load_match.group(3))
        result['load_avg'] = f"{result['load_1']:.2f}, {result['load_5']:.2f}, {result['load_15']:.2f}"

    return result


def parse_df_output(output: str) -> dict:
    """
    Parse df -hT / command output.

    Example output:
    Filesystem     Type  Size  Used Avail Use% Mounted on
    /dev/sda1      ext4  100G   45G   55G  45% /
    """
    result = {
        'disk_total': 'N/A',
        'disk_used': 'N/A',
        'disk_avail': 'N/A',
        'disk_percent': 0,
        'disk_type': 'N/A',
    }

    if not output:
        return result

    lines = output.strip().split('\n')
    if len(lines) < 2:
        return result

    # Parse the data line (skip header)
    # Filesystem Type Size Used Avail Use% Mounted
    parts = lines[1].split()
    if len(parts) >= 6:
        result['disk_type'] = parts[1]
        result['disk_total'] = parts[2]
        result['disk_used'] = parts[3]
        result['disk_avail'] = parts[4]
        # Parse percentage (remove %)
        pct_str = parts[5].replace('%', '')
        try:
            result['disk_percent'] = int(pct_str)
        except ValueError:
            pass

    return result


@login_required
def node_list(request):
    if not request.user.is_superuser:
        # Redirect non-superusers to the pods status page where they can see their own pods
        return redirect("pods_status")

    try:
        base, headers, verify = _load_k8s_auth()
        resp = requests.get(f"{base}/api/v1/nodes", headers=headers, verify=verify)
        resp.raise_for_status()
        items = resp.json().get("items", [])
    except Exception as e:
        messages.error(request, f"Failed to list nodes: {e}")
        items = []

    # Fetch node metrics from metrics-server
    node_metrics = {}
    try:
        metrics_resp = requests.get(
            f"{base}/apis/metrics.k8s.io/v1beta1/nodes",
            headers=headers,
            verify=verify,
            timeout=5
        )
        if metrics_resp.ok:
            for metric in metrics_resp.json().get("items", []):
                name = metric["metadata"]["name"]
                usage = metric.get("usage", {})
                node_metrics[name] = {
                    "cpu": usage.get("cpu", "0"),
                    "memory": usage.get("memory", "0"),
                }
    except Exception as e:
        logger.warning(f"Failed to fetch node metrics: {e}")

    # Fetch node stats via exec (uptime, load average, disk usage)
    node_exec_stats = get_node_stats_via_exec()

    nodes = []
    for item in items:
        addrs = item["status"].get("addresses", [])
        ip = next((a["address"] for a in addrs if a["type"] == "InternalIP"), None)
        ip = ip or (addrs[0]["address"] if addrs else "–")

        conds = {c["type"]: c["status"] for c in item["status"].get("conditions", [])}
        ready = conds.get("Ready") == "True"
        unsched = item["spec"].get("unschedulable", False)

        status = "Ready" if ready and not unsched else (
            "Unschedulable" if unsched else "NotReady"
        )

        # Get allocatable resources (capacity)
        allocatable = item["status"].get("allocatable", {})
        capacity_cpu = allocatable.get("cpu", "0")
        capacity_memory = allocatable.get("memory", "0")

        # Get current usage from metrics
        name = item["metadata"]["name"]
        metrics = node_metrics.get(name, {})
        cpu_usage = metrics.get("cpu", "0")
        memory_usage = metrics.get("memory", "0")

        # Parse and calculate percentages
        cpu_used_millicores = parse_cpu(cpu_usage)
        cpu_capacity_millicores = parse_cpu(capacity_cpu)
        cpu_percent = round(cpu_used_millicores / cpu_capacity_millicores * 100, 1) if cpu_capacity_millicores > 0 else 0

        memory_used_bytes = parse_memory(memory_usage)
        memory_capacity_bytes = parse_memory(capacity_memory)
        memory_percent = round(memory_used_bytes / memory_capacity_bytes * 100, 1) if memory_capacity_bytes > 0 else 0

        # Get exec-based stats (uptime, load average, disk)
        exec_stats = node_exec_stats.get(name, {})

        nodes.append({
            "name": name,
            "ip": ip,
            "start_time": item["metadata"]["creationTimestamp"],
            "status": status,
            # Resource capacity
            "cpu_capacity": capacity_cpu,
            "memory_capacity": format_memory_human(memory_capacity_bytes),
            # Resource usage
            "cpu_used": f"{cpu_used_millicores}m",
            "cpu_percent": cpu_percent,
            "memory_used": format_memory_human(memory_used_bytes),
            "memory_percent": memory_percent,
            # Exec-based stats
            "uptime": exec_stats.get("uptime", "N/A"),
            "load_avg": exec_stats.get("load_avg", "N/A"),
            "load_1": exec_stats.get("load_1", 0),
            "load_5": exec_stats.get("load_5", 0),
            "load_15": exec_stats.get("load_15", 0),
            "disk_total": exec_stats.get("disk_total", "N/A"),
            "disk_used": exec_stats.get("disk_used", "N/A"),
            "disk_avail": exec_stats.get("disk_avail", "N/A"),
            "disk_percent": exec_stats.get("disk_percent", 0),
            "disk_type": exec_stats.get("disk_type", "N/A"),
        })

    # Get latest health status for each component
    health_status = {}
    for component in ['linstor', 'mail_queue', 'mariadb', 'smtp_storage', 'mariadb_storage']:
        latest = SystemHealthStatus.objects.filter(
            component=component
        ).order_by('-checked_at').first()
        health_status[component] = latest

    # Get settings for thresholds display
    sys_settings = SystemSettings.get_settings()

    return render(request, "main/node_list.html", {
        "nodes": nodes,
        "health_status": health_status,
        "sys_settings": sys_settings,
    })


@login_required
def node_detail(request, name):
    if not request.user.is_superuser:
        return redirect("node_list")

    try:
        base, headers, verify = _load_k8s_auth()
        r_node = requests.get(f"{base}/api/v1/nodes/{name}", headers=headers, verify=verify)
        r_node.raise_for_status()
        node = r_node.json()

        sel = f"involvedObject.kind=Node,involvedObject.name={name}"
        r_evt = requests.get(f"{base}/api/v1/events?fieldSelector={sel}",
                            headers=headers, verify=verify)
        r_evt.raise_for_status()
        events = r_evt.json().get("items", [])
    except Exception as e:
        messages.error(request, f"Failed to fetch node detail: {e}")
        node, events = None, []

    return render(request, "main/node_detail.html", {
        "node": node,
        "events": events,
    })


@login_required
def node_cordon(request, name):
    if not request.user.is_superuser:
        return redirect('node_list')

    if request.method == "POST":
        try:
            base, headers, verify = _load_k8s_auth()

            patch_headers = headers.copy()
            patch_headers["Content-Type"] = "application/strategic-merge-patch+json"

            body = {"spec": {"unschedulable": True}}
            resp = requests.patch(
                f"{base}/api/v1/nodes/{name}",
                json=body,
                headers=patch_headers,
                verify=verify
            )

            if not resp.ok:
                messages.error(request,
                    f"Cordon failed (status={resp.status_code}): {resp.text}"
                )
            else:
                messages.success(request, f"Node {name} cordoned successfully.")

        except Exception as e:
            messages.error(request, f"Cordon exception: {e}")

    return redirect('node_list')


@login_required
def node_drain(request, name):
    if not request.user.is_superuser:
        return redirect('node_list')

    if request.method == "POST":
        try:
            base, headers, verify = _load_k8s_auth()

            patch_headers = headers.copy()
            patch_headers["Content-Type"] = "application/strategic-merge-patch+json"
            cordon_body = {"spec": {"unschedulable": True}}
            r1 = requests.patch(
                f"{base}/api/v1/nodes/{name}",
                json=cordon_body,
                headers=patch_headers,
                verify=verify
            )
            if not r1.ok:
                messages.error(request,
                    f"Cordon in drain failed (status={r1.status_code}): {r1.text}"
                )
                return redirect('node_list')

            sel = f"spec.nodeName={name}"
            r2 = requests.get(
                f"{base}/api/v1/pods?fieldSelector={sel}",
                headers=headers,
                verify=verify
            )
            r2.raise_for_status()
            pods = r2.json().get("items", [])

            errors = []
            for p in pods:
                ns = p["metadata"]["namespace"]
                pod = p["metadata"]["name"]
                eviction = {
                    "apiVersion": "policy/v1",
                    "kind": "Eviction",
                    "metadata": {"name": pod, "namespace": ns}
                }
                ev_url = f"{base}/api/v1/namespaces/{ns}/pods/{pod}/eviction"
                rev = requests.post(
                    ev_url,
                    json=eviction,
                    headers=headers,
                    verify=verify
                )
                if not rev.ok:
                    errors.append(f"{pod}@{ns}: {rev.status_code}")

            if errors:
                messages.warning(
                    request,
                    f"Drained (cordoned) but evictions failed for: {', '.join(errors)}"
                )
            else:
                messages.success(request, f"Node {name} drained successfully.")

        except Exception as e:
            messages.error(request, f"Drain exception: {e}")

    return redirect('node_list')


@login_required
def node_uncordon(request, name):
    if not request.user.is_superuser:
        return redirect('node_list')

    if request.method == "POST":
        try:
            base, headers, verify = _load_k8s_auth()

            patch_headers = headers.copy()
            patch_headers["Content-Type"] = "application/strategic-merge-patch+json"

            body = {"spec": {"unschedulable": False}}
            resp = requests.patch(
                f"{base}/api/v1/nodes/{name}",
                json=body,
                headers=patch_headers,
                verify=verify
            )

            if not resp.ok:
                messages.error(
                    request,
                    f"Uncordon failed (status={resp.status_code}): {resp.text}"
                )
            else:
                messages.success(request, f"Node {name} uncordoned successfully.")

        except Exception as e:
            messages.error(request, f"Uncordon exception: {e}")

    return redirect('node_list')


@login_required
def pod_logs(request, namespace, name):
    is_super = request.user.is_superuser
    try:
        base, headers, verify = _load_k8s_auth()
    except Exception as e:
        messages.error(request, f"Error loading Kubernetes credentials: {e}")
        return redirect('pods_status')

    try:
        pod_resp = requests.get(f"{base}/api/v1/namespaces/{namespace}/pods/{name}", headers=headers, verify=verify, timeout=10)
    except Exception as e:
        messages.error(request, f"Error fetching pod details: {e}")
        return redirect('pods_status')

    if not pod_resp.ok:
        messages.error(request, f"Could not fetch pod details (status={pod_resp.status_code}): {pod_resp.text}")
        return redirect('pods_status')

    pod_json = pod_resp.json()
    labels = pod_json.get('metadata', {}).get('labels', {})
    group_label = labels.get('group')

    if not is_super:
        user_slugs = [d.replace('.', '-') for d in Domain.objects.filter(owner=request.user).values_list('domain_name', flat=True)]
        if not group_label or group_label not in user_slugs:
            messages.error(request, "You are not authorized to view logs for this pod.")
            return redirect('pods_status')

    container_specs = pod_json.get('spec', {}).get('containers', [])
    container_names = [c.get('name') for c in container_specs]

    logs_by_container = {}
    for c in container_names:
        try:
            log_resp = requests.get(f"{base}/api/v1/namespaces/{namespace}/pods/{name}/log", headers=headers, verify=verify, params={'container': c}, timeout=10)
            if log_resp.ok:
                logs_by_container[c] = log_resp.text.splitlines()
            else:
                messages.error(request, f"Failed to fetch logs for container '{c}' (status={log_resp.status_code}): {log_resp.text}")
                logs_by_container[c] = []
        except Exception as e:
            messages.error(request, f"Error fetching logs for container '{c}': {e}")
            logs_by_container[c] = []

    return render(request, 'main/pod_logs.html', {'namespace': namespace, 'pod_name': name, 'logs_by_container': logs_by_container})


@login_required(login_url="/dashboard/")
def backup_logs(request, domain, jobid):
    base, headers, ca_cert = _load_k8s_auth()
    namespace = "kubepanel"
    ns_domain = domain.replace(".", "-")
    job_name = f"backup-{ns_domain}-{jobid}"
    pods_url = f"{base}/api/v1/namespaces/{namespace}/pods"
    params = {"labelSelector": f"job-name={job_name}"}

    try:
        r = requests.get(pods_url, headers=headers, params=params,
                        verify=ca_cert, timeout=5)
        r.raise_for_status()
        items = r.json().get("items", [])
        if items:
            pod = items[0]
            pod_name = pod["metadata"]["name"]
            log_url = (f"{base}/api/v1/namespaces/{namespace}"
                      f"/pods/{pod_name}/log")
            r2 = requests.get(log_url, headers=headers,
                             verify=ca_cert, timeout=10)
            if r2.status_code == 200:
                lines = r2.text.splitlines()
            else:
                lines = [f"Error {r2.status_code}: {r2.text}"]
            logs_by_container = {pod_name: lines}
            display_name = pod_name
        else:
            display_name = job_name
            logs_by_container = {}
    except Exception as e:
        display_name = job_name
        logs_by_container = {
            display_name: [f"Exception fetching logs: {e}"]
        }

    return render(request, "main/backup_logs.html", {
        "domain": domain,
        "namespace": namespace,
        "pod_name": display_name,
        "logs_by_container": logs_by_container,
    })


@login_required
def get_pods_status(request):
    is_super = request.user.is_superuser

    label_selector = None
    if not is_super:
        user_domains = list(
            Domain.objects
                  .filter(owner=request.user)
                  .values_list("domain_name", flat=True)
        )

        if not user_domains:
            return render(request, "main/pods_status.html", {"pods": []})

        slugs = [d.replace(".", "-") for d in user_domains]

        if len(slugs) == 1:
            label_selector = f"group={slugs[0]}"
        else:
            label_selector = f"group in ({','.join(slugs)})"

    try:
        base, headers, verify = _load_k8s_auth()
    except Exception as e:
        messages.error(request, f"Failed to load Kubernetes credentials: {e}")
        return render(request, "main/pods_status.html", {"pods": []})

    url = f"{base}/api/v1/pods"
    if label_selector:
        url += f"?labelSelector={label_selector}"

    try:
        resp = requests.get(url, headers=headers, verify=verify, timeout=10)
        resp.raise_for_status()
        items = resp.json().get("items", [])
    except requests.exceptions.RequestException as e:
        messages.error(request, f"Failed to fetch pods: {e}")
        return render(request, "main/pods_status.html", {"pods": []})

    pods_info = []
    for pod in items:
        md = pod.get("metadata", {})
        spec = pod.get("spec", {})
        st = pod.get("status", {})

        phase = "Terminating" if md.get("deletionTimestamp") else st.get("phase", "Unknown")

        pods_info.append({
            "name": md.get("name"),
            "namespace": md.get("namespace"),
            "node": spec.get("nodeName", "Unknown"),
            "status": phase,
            "ip": st.get("podIP", "N/A"),
            "host_ip": st.get("hostIP", "N/A"),
            "containers": len(spec.get("containers", [])),
        })

    return render(request, "main/pods_status.html", {"pods": pods_info})
