"""
Kubernetes node and pod management views
"""
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.contrib import messages

import os
import requests
import logging

from dashboard.models import Domain
from .utils import _load_k8s_auth

logger = logging.getLogger("django")


@login_required
def node_list(request):
    if not request.user.is_superuser:
        return redirect("node_list")

    try:
        base, headers, verify = _load_k8s_auth()
        resp = requests.get(f"{base}/api/v1/nodes", headers=headers, verify=verify)
        resp.raise_for_status()
        items = resp.json().get("items", [])
    except Exception as e:
        messages.error(request, f"Failed to list nodes: {e}")
        items = []

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
        nodes.append({
            "name": item["metadata"]["name"],
            "ip": ip,
            "start_time": item["metadata"]["creationTimestamp"],
            "status": status,
        })

    return render(request, "main/node_list.html", {"nodes": nodes})


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

    host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    ca_cert_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

    try:
        token = open(token_path).read().strip()
    except FileNotFoundError:
        return JsonResponse({"error": "Kubernetes token file not found."}, status=500)

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    url = f"https://{host}:{port}/api/v1/pods"
    if label_selector:
        url += f"?labelSelector={label_selector}"

    try:
        resp = requests.get(url, headers=headers, verify=ca_cert_path)
        resp.raise_for_status()
        items = resp.json().get("items", [])
    except requests.exceptions.RequestException as e:
        return JsonResponse({"error": str(e)}, status=500)

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
