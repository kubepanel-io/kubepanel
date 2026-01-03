"""
SMTP Firewall views

Admin-only views for monitoring SMTP traffic and managing sender blocklists
via rspamd and Redis.
"""
import logging
import json
from datetime import datetime

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import JsonResponse

import redis
import requests

logger = logging.getLogger("django")

# Redis and rspamd connection settings
REDIS_HOST = "redis.kubepanel.svc.cluster.local"
REDIS_PORT = 6379
RSPAMD_HOST = "rspamd.kubepanel.svc.cluster.local"
RSPAMD_PORT = 11334


def is_superuser(user):
    """Check if user is superuser (admin)."""
    return user.is_superuser


def get_redis_client():
    """Get Redis client connection."""
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


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

    try:
        response = requests.get(
            f"http://{RSPAMD_HOST}:{RSPAMD_PORT}/history",
            params={'limit': 100},
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
        'error_message': error_message,
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
        limit = min(limit, 500)  # Cap at 500

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
    """
    blocked_senders = []
    blocked_domains = []
    blocked_ips = []
    error_message = None

    try:
        r = get_redis_client()

        # Get all blocked items from Redis sets
        blocked_senders = list(r.smembers('blocked_senders'))
        blocked_domains = list(r.smembers('blocked_domains'))
        blocked_ips = list(r.smembers('blocked_ips'))

        # Sort for consistent display
        blocked_senders.sort()
        blocked_domains.sort()
        blocked_ips.sort()

    except redis.exceptions.ConnectionError:
        error_message = "Cannot connect to Redis. Is it running?"
        logger.warning(f"Redis connection failed: {error_message}")
    except redis.exceptions.RedisError as e:
        error_message = f"Redis error: {e}"
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

    # Map rule type to Redis key
    redis_key_map = {
        'sender': 'blocked_senders',
        'domain': 'blocked_domains',
        'ip': 'blocked_ips',
    }
    redis_key = redis_key_map[rule_type]

    try:
        r = get_redis_client()

        # Check if already exists
        if r.sismember(redis_key, value):
            messages.warning(request, f"'{value}' is already blocked.")
            return redirect('smtp_firewall_list')

        # Add to blocklist
        r.sadd(redis_key, value)
        messages.success(request, f"Added '{value}' to blocked {rule_type}s.")

    except redis.exceptions.ConnectionError:
        messages.error(request, "Cannot connect to Redis. Is it running?")
    except redis.exceptions.RedisError as e:
        logger.error(f"Failed to add SMTP block rule: {e}")
        messages.error(request, f"Failed to add rule: {e}")

    return redirect('smtp_firewall_list')


@login_required
@user_passes_test(is_superuser, login_url='/dashboard/')
def smtp_firewall_delete_rule(request, rule_type, value):
    """
    Remove a sender, domain, or IP from the SMTP blocklist.
    """
    if request.method != 'POST':
        return redirect('smtp_firewall_list')

    # Validate rule type
    if rule_type not in ('sender', 'domain', 'ip'):
        messages.error(request, "Invalid rule type.")
        return redirect('smtp_firewall_list')

    # Map rule type to Redis key
    redis_key_map = {
        'sender': 'blocked_senders',
        'domain': 'blocked_domains',
        'ip': 'blocked_ips',
    }
    redis_key = redis_key_map[rule_type]

    try:
        r = get_redis_client()

        # Remove from blocklist
        removed = r.srem(redis_key, value)
        if removed:
            messages.success(request, f"Removed '{value}' from blocked {rule_type}s.")
        else:
            messages.warning(request, f"'{value}' was not in the blocklist.")

    except redis.exceptions.ConnectionError:
        messages.error(request, "Cannot connect to Redis. Is it running?")
    except redis.exceptions.RedisError as e:
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
    View and display current rate limit settings.

    Note: Rate limit configuration is in rspamd ConfigMap.
    This view displays the current settings for reference.
    """
    # Rate limits are defined in rspamd ConfigMap - display for reference
    rate_limits = {
        'user': {'rate': '100 / 1h', 'burst': 20, 'description': 'Per authenticated user'},
        'from_domain': {'rate': '500 / 1h', 'burst': 50, 'description': 'Per sender domain'},
        'to': {'rate': '200 / 1h', 'burst': 30, 'description': 'Per recipient'},
    }

    context = {
        'rate_limits': rate_limits,
    }
    return render(request, 'main/smtp_rate_limits.html', context)


# =============================================================================
# Quick Block from Traffic View
# =============================================================================

@login_required
@user_passes_test(is_superuser, login_url='/dashboard/')
def smtp_quick_block(request):
    """
    Quick block action from traffic view - add sender or domain to blocklist.

    Accepts POST with 'sender' parameter and optionally 'block_domain' checkbox.
    """
    if request.method != 'POST':
        return redirect('smtp_traffic')

    sender = request.POST.get('sender', '').strip().lower()
    block_domain = request.POST.get('block_domain') == 'on'

    if not sender:
        messages.error(request, "Sender address is required.")
        return redirect('smtp_traffic')

    try:
        r = get_redis_client()

        if block_domain:
            # Extract domain from sender
            if '@' in sender:
                domain = sender.split('@')[1]
                r.sadd('blocked_domains', domain)
                messages.success(request, f"Blocked entire domain: @{domain}")
            else:
                messages.error(request, "Invalid sender address format.")
        else:
            # Block specific sender
            r.sadd('blocked_senders', sender)
            messages.success(request, f"Blocked sender: {sender}")

    except redis.exceptions.ConnectionError:
        messages.error(request, "Cannot connect to Redis. Is it running?")
    except redis.exceptions.RedisError as e:
        logger.error(f"Failed to quick block: {e}")
        messages.error(request, f"Failed to block sender: {e}")

    return redirect('smtp_traffic')
