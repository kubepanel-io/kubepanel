"""
Monitoring views (live traffic, etc.)
"""
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.contrib.auth.decorators import login_required
from datetime import datetime, timezone

import os
import json
import requests

from .utils import get_country_info, is_static_file


def sort_logs_by_time(logs):
    return sorted(logs, key=lambda log: datetime.fromisoformat(log["time"]))


def fetch_ingress_logs(since_seconds=300):
    """
    Fetch logs from all ingress pods.

    Args:
        since_seconds: Number of seconds of logs to fetch (default: 300 = 5 minutes)

    Returns:
        List of parsed log entries with country info added
    """
    host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    ca_cert_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

    with open(token_path, 'r') as f:
        token = f.read().strip()

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    namespace = "ingress"
    url = f"https://{host}:{port}/api/v1/namespaces/{namespace}/pods"
    response = requests.get(url, headers=headers, verify=ca_cert_path)
    response.raise_for_status()

    pods = response.json()["items"]
    logs = []

    # Cap at 24 hours max, minimum 60 seconds
    since_seconds = max(60, min(since_seconds, 86400))

    for pod in pods:
        pod_name = pod["metadata"]["name"]
        # Add protection limit: limitBytes=5MB (no tailLines - it shows last N lines, not first N)
        log_url = (
            f"https://{host}:{port}/api/v1/namespaces/{namespace}/pods/{pod_name}/log"
            f"?sinceSeconds={since_seconds}&limitBytes=5000000"
        )
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
                    pass  # Skip non-JSON lines silently
            logs.extend(pod_logs)

    logs = sort_logs_by_time(logs)

    # Add country info for each log
    for log in logs:
        ip = log.get("x_forwarded_for", "").split(",")[0].strip()
        if ip:
            country_info = get_country_info(ip)
            log["country_name"] = country_info["country_name"]
            log["flag_url"] = country_info["flag_url"]

    return logs


def calculate_stats(logs):
    """Calculate traffic statistics from logs."""
    total = len(logs)
    success = 0
    client_errors = 0
    server_errors = 0

    for log in logs:
        status = log.get("status", 0)
        if 200 <= status < 300:
            success += 1
        elif 400 <= status < 500:
            client_errors += 1
        elif status >= 500:
            server_errors += 1

    return {
        "total": total,
        "success": success,
        "client_errors": client_errors,
        "server_errors": server_errors,
    }


@login_required(login_url="/dashboard/")
def livetraffic(request):
    """Main livetraffic page view."""
    if not request.user.is_superuser:
        return HttpResponse("Permission denied")

    # Get timeframe from query params (default: 5 minutes)
    since_minutes = int(request.GET.get('since_minutes', 5))
    since_time = request.GET.get('since_time')  # ISO format datetime

    if since_time:
        try:
            # Parse ISO datetime and calculate seconds from now
            since_dt = datetime.fromisoformat(since_time.replace('Z', '+00:00'))
            if since_dt.tzinfo is None:
                since_dt = since_dt.replace(tzinfo=timezone.utc)
            since_seconds = int((datetime.now(timezone.utc) - since_dt).total_seconds())
        except (ValueError, TypeError):
            since_seconds = since_minutes * 60
    else:
        since_seconds = since_minutes * 60

    logs = fetch_ingress_logs(since_seconds)

    return render(request, "main/livetraffic.html", {
        "logs": logs,
        "since_minutes": since_minutes,
        "since_time": since_time,
    })


@login_required(login_url="/dashboard/")
def livetraffic_api(request):
    """AJAX endpoint for auto-refresh - returns JSON."""
    if not request.user.is_superuser:
        return JsonResponse({"error": "Permission denied"}, status=403)

    # Get timeframe from query params (default: 5 minutes)
    since_minutes = int(request.GET.get('since_minutes', 5))
    since_time = request.GET.get('since_time')  # ISO format datetime

    if since_time:
        try:
            # Parse ISO datetime and calculate seconds from now
            since_dt = datetime.fromisoformat(since_time.replace('Z', '+00:00'))
            if since_dt.tzinfo is None:
                since_dt = since_dt.replace(tzinfo=timezone.utc)
            since_seconds = int((datetime.now(timezone.utc) - since_dt).total_seconds())
        except (ValueError, TypeError):
            since_seconds = since_minutes * 60
    else:
        since_seconds = since_minutes * 60

    logs = fetch_ingress_logs(since_seconds)
    stats = calculate_stats(logs)

    return JsonResponse({
        "logs": logs,
        "stats": stats,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@login_required(login_url="/dashboard/")
def user_livetraffic(request):
    """
    Live traffic view for regular users.

    Shows only traffic for domains owned by the logged-in user.
    Only offers WAF blocking (no L3 Firewall option).
    """
    from dashboard.models import Domain

    # Get user's domains and all their hostnames
    user_domains = Domain.objects.filter(owner=request.user).prefetch_related('aliases')
    user_hostnames = set()
    domain_lookup = {}  # hostname -> domain_name mapping

    for domain in user_domains:
        for hostname in domain.all_hostnames:
            user_hostnames.add(hostname)
            domain_lookup[hostname] = domain.domain_name

    # Get timeframe from query params (default: 5 minutes)
    since_minutes = int(request.GET.get('since_minutes', 5))
    since_time = request.GET.get('since_time')  # ISO format datetime

    if since_time:
        try:
            since_dt = datetime.fromisoformat(since_time.replace('Z', '+00:00'))
            if since_dt.tzinfo is None:
                since_dt = since_dt.replace(tzinfo=timezone.utc)
            since_seconds = int((datetime.now(timezone.utc) - since_dt).total_seconds())
        except (ValueError, TypeError):
            since_seconds = since_minutes * 60
    else:
        since_seconds = since_minutes * 60

    # Fetch all logs and filter by user's hostnames
    all_logs = fetch_ingress_logs(since_seconds)
    logs = []
    for log in all_logs:
        vhost = log.get('vhost', '')
        if vhost in user_hostnames:
            # Add domain_name for WAF linking
            log['domain_name'] = domain_lookup.get(vhost, vhost)
            logs.append(log)

    return render(request, "main/user_livetraffic.html", {
        "logs": logs,
        "since_minutes": since_minutes,
        "since_time": since_time,
        "user_domains": user_domains,
    })


@login_required(login_url="/dashboard/")
def user_livetraffic_api(request):
    """
    AJAX endpoint for user livetraffic auto-refresh.

    Returns JSON with logs filtered to user's domains only.
    """
    from dashboard.models import Domain

    # Get user's domains and all their hostnames
    user_domains = Domain.objects.filter(owner=request.user).prefetch_related('aliases')
    user_hostnames = set()
    domain_lookup = {}

    for domain in user_domains:
        for hostname in domain.all_hostnames:
            user_hostnames.add(hostname)
            domain_lookup[hostname] = domain.domain_name

    # Get timeframe from query params (default: 5 minutes)
    since_minutes = int(request.GET.get('since_minutes', 5))
    since_time = request.GET.get('since_time')

    if since_time:
        try:
            since_dt = datetime.fromisoformat(since_time.replace('Z', '+00:00'))
            if since_dt.tzinfo is None:
                since_dt = since_dt.replace(tzinfo=timezone.utc)
            since_seconds = int((datetime.now(timezone.utc) - since_dt).total_seconds())
        except (ValueError, TypeError):
            since_seconds = since_minutes * 60
    else:
        since_seconds = since_minutes * 60

    # Fetch all logs and filter by user's hostnames
    all_logs = fetch_ingress_logs(since_seconds)
    logs = []
    for log in all_logs:
        vhost = log.get('vhost', '')
        if vhost in user_hostnames:
            log['domain_name'] = domain_lookup.get(vhost, vhost)
            logs.append(log)

    stats = calculate_stats(logs)

    return JsonResponse({
        "logs": logs,
        "stats": stats,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
