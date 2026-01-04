"""
SMTP Firewall views

Admin-only views for monitoring SMTP traffic and managing sender blocklists
via rspamd and Kubernetes SMTPFirewall CRD.
"""
import logging
import json
from datetime import datetime

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import JsonResponse

import requests

from dashboard.k8s import (
    get_or_create_smtp_firewall,
    add_blocked_sender,
    remove_blocked_sender,
    add_blocked_domain,
    remove_blocked_domain,
    add_blocked_ip,
    remove_blocked_ip,
    add_rate_limit,
    remove_rate_limit,
    K8sClientError,
)

logger = logging.getLogger("django")

# rspamd connection settings (for traffic history only)
RSPAMD_HOST = "rspamd.kubepanel.svc.cluster.local"
RSPAMD_PORT = 11334


def is_superuser(user):
    """Check if user is superuser (admin)."""
    return user.is_superuser


# =============================================================================
# SMTP Traffic Monitoring Views
# =============================================================================

@login_required
@user_passes_test(is_superuser, login_url='/dashboard/')
def smtp_traffic(request):
    """
    Display SMTP traffic history from rspamd.

    Admin only - shows recent email transactions with sender, recipient,
    action taken, and any symbols triggered.
    """
    history = []
    error_message = None

    # Get limit from query param (default 100, max 1000)
    try:
        limit = int(request.GET.get('limit', 100))
        limit = min(max(limit, 1), 1000)
    except (ValueError, TypeError):
        limit = 100

    try:
        response = requests.get(
            f"http://{RSPAMD_HOST}:{RSPAMD_PORT}/history",
            params={'limit': limit},
            timeout=10
        )
        response.raise_for_status()
        data = response.json()

        # rspamd returns history in 'rows' key
        history = data.get('rows', [])

        # Parse and format timestamps
        for item in history:
            if 'unix_time' in item:
                item['time_formatted'] = datetime.fromtimestamp(
                    item['unix_time']
                ).strftime('%Y-%m-%d %H:%M:%S')

    except requests.exceptions.ConnectionError:
        error_message = "Cannot connect to rspamd. Is it running?"
        logger.warning(f"rspamd connection failed: {error_message}")
    except requests.exceptions.Timeout:
        error_message = "rspamd request timed out."
        logger.warning(f"rspamd timeout: {error_message}")
    except requests.exceptions.RequestException as e:
        error_message = f"Error fetching SMTP history: {e}"
        logger.error(error_message)
    except json.JSONDecodeError as e:
        error_message = f"Invalid response from rspamd: {e}"
        logger.error(error_message)

    context = {
        'history': history,
        'history_json': json.dumps(history),
        'error_message': error_message,
        'limit': limit,
    }
    return render(request, 'main/smtp_traffic.html', context)


@login_required
@user_passes_test(is_superuser, login_url='/dashboard/')
def smtp_traffic_api(request):
    """
    API endpoint to fetch SMTP traffic data for AJAX refresh.

    Returns JSON with recent transactions.
    """
    try:
        limit = int(request.GET.get('limit', 100))
        limit = min(limit, 1000)  # Cap at 1000

        response = requests.get(
            f"http://{RSPAMD_HOST}:{RSPAMD_PORT}/history",
            params={'limit': limit},
            timeout=10
        )
        response.raise_for_status()
        data = response.json()

        history = data.get('rows', [])

        # Format timestamps
        for item in history:
            if 'unix_time' in item:
                item['time_formatted'] = datetime.fromtimestamp(
                    item['unix_time']
                ).strftime('%Y-%m-%d %H:%M:%S')

        return JsonResponse({'success': True, 'history': history})

    except Exception as e:
        logger.error(f"SMTP traffic API error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# =============================================================================
# SMTP Firewall Block Rules Views
# =============================================================================

@login_required
@user_passes_test(is_superuser, login_url='/dashboard/')
def smtp_firewall_list(request):
    """
    Display SMTP firewall blocklist and rate limit settings.

    Admin only - shows blocked senders, domains, and IPs.
    Reads from SMTPFirewall CRD via K8s API.
    """
    blocked_senders = []
    blocked_domains = []
    blocked_ips = []
    error_message = None

    try:
        fw = get_or_create_smtp_firewall()

        # Get all blocked items from CRD
        blocked_senders = sorted(fw.blocked_senders)
        blocked_domains = sorted(fw.blocked_domains)
        blocked_ips = sorted(fw.blocked_ips)

    except K8sClientError as e:
        error_message = f"Cannot connect to Kubernetes: {e}"
        logger.warning(f"K8s connection failed: {error_message}")
    except Exception as e:
        error_message = f"Error: {e}"
        logger.error(error_message)

    context = {
        'blocked_senders': blocked_senders,
        'blocked_domains': blocked_domains,
        'blocked_ips': blocked_ips,
        'error_message': error_message,
    }
    return render(request, 'main/smtp_firewall.html', context)


@login_required
@user_passes_test(is_superuser, login_url='/dashboard/')
def smtp_firewall_add_rule(request):
    """
    Add a sender, domain, or IP to the SMTP blocklist.
    Updates SMTPFirewall CRD.
    """
    if request.method != 'POST':
        return redirect('smtp_firewall_list')

    rule_type = request.POST.get('rule_type', '').strip()
    value = request.POST.get('value', '').strip().lower()

    if not value:
        messages.error(request, "Value cannot be empty.")
        return redirect('smtp_firewall_list')

    # Validate rule type
    if rule_type not in ('sender', 'domain', 'ip'):
        messages.error(request, "Invalid rule type.")
        return redirect('smtp_firewall_list')

    try:
        if rule_type == 'sender':
            add_blocked_sender(value)
        elif rule_type == 'domain':
            add_blocked_domain(value)
        elif rule_type == 'ip':
            add_blocked_ip(value)

        messages.success(request, f"Added '{value}' to blocked {rule_type}s.")

    except K8sClientError as e:
        logger.error(f"Failed to add SMTP block rule: {e}")
        messages.error(request, f"Failed to add rule: {e}")
    except Exception as e:
        logger.error(f"Failed to add SMTP block rule: {e}")
        messages.error(request, f"Failed to add rule: {e}")

    return redirect('smtp_firewall_list')


@login_required
@user_passes_test(is_superuser, login_url='/dashboard/')
def smtp_firewall_delete_rule(request, rule_type, value):
    """
    Remove a sender, domain, or IP from the SMTP blocklist.
    Updates SMTPFirewall CRD.
    """
    if request.method != 'POST':
        return redirect('smtp_firewall_list')

    # Validate rule type
    if rule_type not in ('sender', 'domain', 'ip'):
        messages.error(request, "Invalid rule type.")
        return redirect('smtp_firewall_list')

    try:
        if rule_type == 'sender':
            remove_blocked_sender(value)
        elif rule_type == 'domain':
            remove_blocked_domain(value)
        elif rule_type == 'ip':
            remove_blocked_ip(value)

        messages.success(request, f"Removed '{value}' from blocked {rule_type}s.")

    except K8sClientError as e:
        logger.error(f"Failed to delete SMTP block rule: {e}")
        messages.error(request, f"Failed to delete rule: {e}")
    except Exception as e:
        logger.error(f"Failed to delete SMTP block rule: {e}")
        messages.error(request, f"Failed to delete rule: {e}")

    return redirect('smtp_firewall_list')


# =============================================================================
# Rate Limit Views
# =============================================================================

@login_required
@user_passes_test(is_superuser, login_url='/dashboard/')
def smtp_rate_limits(request):
    """
    View and manage per-user rate limit settings.

    Global defaults are in rspamd ConfigMap.
    Per-user overrides are stored in SMTPFirewall CRD.
    """
    user_limits = []
    error_message = None

    # Global defaults (from rspamd config)
    global_defaults = {
        'user': {'rate': '100 / 1h', 'description': 'Default per-user limit'},
        'from_domain': {'rate': '500 / 1h', 'description': 'Per sender domain'},
        'to': {'rate': '200 / 1h', 'description': 'Per recipient'},
    }

    try:
        fw = get_or_create_smtp_firewall()

        # Get all per-user rate limits from CRD
        for rl in fw.rate_limits:
            user_limits.append({'user': rl.user, 'rate': rl.rate})

        # Sort by user
        user_limits.sort(key=lambda x: x['user'])

    except K8sClientError as e:
        error_message = f"Cannot connect to Kubernetes: {e}"
        logger.warning(f"K8s connection failed: {error_message}")
    except Exception as e:
        error_message = f"Error: {e}"
        logger.error(error_message)

    context = {
        'global_defaults': global_defaults,
        'user_limits': user_limits,
        'error_message': error_message,
    }
    return render(request, 'main/smtp_rate_limits.html', context)


@login_required
@user_passes_test(is_superuser, login_url='/dashboard/')
def smtp_rate_limit_add(request):
    """
    Add a per-user rate limit.
    Updates SMTPFirewall CRD.
    """
    if request.method != 'POST':
        return redirect('smtp_rate_limits')

    user = request.POST.get('user', '').strip().lower()
    rate = request.POST.get('rate', '').strip()
    period = request.POST.get('period', '1h').strip()

    if not user or not rate:
        messages.error(request, "User and rate are required.")
        return redirect('smtp_rate_limits')

    # Validate rate is a number
    try:
        rate_num = int(rate)
        if rate_num <= 0:
            raise ValueError("Rate must be positive")
    except ValueError:
        messages.error(request, "Rate must be a positive number.")
        return redirect('smtp_rate_limits')

    # Format: "100 / 1h"
    rate_string = f"{rate_num} / {period}"

    try:
        add_rate_limit(user, rate_string)
        messages.success(request, f"Set rate limit for {user}: {rate_string}")

    except K8sClientError as e:
        logger.error(f"Failed to add rate limit: {e}")
        messages.error(request, f"Failed to add rate limit: {e}")
    except Exception as e:
        logger.error(f"Failed to add rate limit: {e}")
        messages.error(request, f"Failed to add rate limit: {e}")

    return redirect('smtp_rate_limits')


@login_required
@user_passes_test(is_superuser, login_url='/dashboard/')
def smtp_rate_limit_delete(request, user):
    """
    Delete a per-user rate limit.
    Updates SMTPFirewall CRD.
    """
    if request.method != 'POST':
        return redirect('smtp_rate_limits')

    try:
        remove_rate_limit(user)
        messages.success(request, f"Removed rate limit for {user}. User will use default limit.")

    except K8sClientError as e:
        logger.error(f"Failed to delete rate limit: {e}")
        messages.error(request, f"Failed to delete rate limit: {e}")
    except Exception as e:
        logger.error(f"Failed to delete rate limit: {e}")
        messages.error(request, f"Failed to delete rate limit: {e}")

    return redirect('smtp_rate_limits')


# =============================================================================
# Quick Block from Traffic View
# =============================================================================

@login_required
@user_passes_test(is_superuser, login_url='/dashboard/')
def smtp_quick_block(request):
    """
    Quick block action from traffic view - add sender or domain to blocklist.

    Accepts POST with 'sender' parameter and optionally 'block_domain' checkbox.
    Updates SMTPFirewall CRD.
    """
    if request.method != 'POST':
        return redirect('smtp_traffic')

    sender = request.POST.get('sender', '').strip().lower()
    block_domain = request.POST.get('block_domain') == 'on'

    if not sender:
        messages.error(request, "Sender address is required.")
        return redirect('smtp_traffic')

    try:
        if block_domain:
            # Extract domain from sender
            if '@' in sender:
                domain = sender.split('@')[1]
                add_blocked_domain(domain)
                messages.success(request, f"Blocked entire domain: @{domain}")
            else:
                messages.error(request, "Invalid sender address format.")
        else:
            # Block specific sender
            add_blocked_sender(sender)
            messages.success(request, f"Blocked sender: {sender}")

    except K8sClientError as e:
        logger.error(f"Failed to quick block: {e}")
        messages.error(request, f"Failed to block sender: {e}")
    except Exception as e:
        logger.error(f"Failed to quick block: {e}")
        messages.error(request, f"Failed to block sender: {e}")

    return redirect('smtp_traffic')
