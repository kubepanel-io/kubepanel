"""
Monitoring views (live traffic, etc.)
"""
from django.shortcuts import render
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from datetime import datetime

import os
import json
import requests

from .utils import get_country_info, is_static_file


def sort_logs_by_time(logs):
    return sorted(logs, key=lambda log: datetime.fromisoformat(log["time"]))


@login_required(login_url="/dashboard/")
def livetraffic(request):
    if request.user.is_superuser:
        host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        ca_cert_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

        with open(token_path, 'r') as f:
            token = f.read().strip()

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": f"application/json"
        }

        namespace = "ingress"
        url = f"https://{host}:{port}/api/v1/namespaces/{namespace}/pods"
        response = requests.get(url, headers=headers, verify=ca_cert_path)
        response.raise_for_status()

        pods = response.json()["items"]
        logs = []
        for pod in pods:
            pod_name = pod["metadata"]["name"]
            log_url = f"https://{host}:{port}/api/v1/namespaces/{namespace}/pods/{pod_name}/log?sinceSeconds=3600"
            response = requests.get(log_url, headers=headers, verify=ca_cert_path)

            if response.status_code == 200:
                pod_logs = []
                for line in response.text.splitlines():
                    if not line.strip():
                        continue
                    try:
                        parsed_line = json.loads(line)
                        parsed_line["pod_name"] = pod_name
                        if not is_static_file(parsed_line):
                            pod_logs.append(parsed_line)
                    except json.JSONDecodeError:
                        print(f"Skipping non-JSON line: {line}")
                logs.extend(pod_logs)

        logs = sort_logs_by_time(logs)
        for log in logs:
            ip = log.get("x_forwarded_for", "").split(",")[0].strip()
            if ip:
                country_info = get_country_info(ip)
                log["country_name"] = country_info["country_name"]
                log["flag_url"] = country_info["flag_url"]

        return render(request, "main/livetraffic.html", {"logs": logs})
    else:
        return HttpResponse("Permission denied")
