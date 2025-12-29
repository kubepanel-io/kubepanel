"""
Global WAF (Web Application Firewall) views

Admin-only views for managing GlobalWAF rules on ingress-nginx.
"""
import logging

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages

from dashboard.k8s import (
    get_or_create_globalwaf,
    get_globalwaf,
    patch_globalwaf,
    set_globalwaf_enabled,
    add_waf_rule,
    update_waf_rule,
    delete_waf_rule,
    get_waf_rule,
    K8sClientError,
    K8sNotFoundError,
)

logger = logging.getLogger("django")


def is_superuser(user):
    """Check if user is superuser (admin)."""
    return user.is_superuser


@login_required
@user_passes_test(is_superuser, login_url='/dashboard/')
def global_waf_list(request):
    """
    Display GlobalWAF status and rules list.

    Admin only - shows all WAF rules with enable/disable toggle.
    """
    try:
        globalwaf = get_or_create_globalwaf()
    except K8sClientError as e:
        logger.error(f"Failed to get GlobalWAF CR: {e}")
        messages.error(request, f"Failed to load WAF configuration: {e}")
        globalwaf = None

    context = {
        'globalwaf': globalwaf,
        'rules': globalwaf.rules if globalwaf else [],
        'status': globalwaf.status if globalwaf else None,
    }
    return render(request, 'main/global_waf.html', context)


@login_required
@user_passes_test(is_superuser, login_url='/dashboard/')
def global_waf_toggle(request):
    """
    Toggle GlobalWAF enabled/disabled state.
    """
    if request.method != 'POST':
        return redirect('global_waf_list')

    try:
        globalwaf = get_globalwaf()
        new_state = not globalwaf.enabled
        set_globalwaf_enabled(enabled=new_state)

        state_text = "enabled" if new_state else "disabled"
        messages.success(request, f"Global WAF has been {state_text}.")
    except K8sNotFoundError:
        messages.error(request, "GlobalWAF CR not found.")
    except K8sClientError as e:
        logger.error(f"Failed to toggle GlobalWAF: {e}")
        messages.error(request, f"Failed to toggle WAF: {e}")

    return redirect('global_waf_list')


@login_required
@user_passes_test(is_superuser, login_url='/dashboard/')
def global_waf_add_rule(request):
    """
    Add a new WAF rule.
    """
    if request.method == 'POST':
        # Build rule from form data
        rule = _build_rule_from_post(request.POST)

        # Validate rule has at least one condition
        if not rule.get('domain') and not rule.get('ip') and not rule.get('path'):
            messages.error(request, "At least one of Domain, IP, or Path is required.")
            return render(request, 'main/global_waf_rule_form.html', {
                'rule': rule,
                'edit_mode': False,
            })

        try:
            add_waf_rule(rule)
            messages.success(request, "WAF rule added successfully.")
            return redirect('global_waf_list')
        except K8sClientError as e:
            logger.error(f"Failed to add WAF rule: {e}")
            messages.error(request, f"Failed to add rule: {e}")
            return render(request, 'main/global_waf_rule_form.html', {
                'rule': rule,
                'edit_mode': False,
            })

    # GET - show form, pre-fill from query params if provided
    rule = {
        'action': 'block',
        'pathMatchType': 'prefix',
    }

    # Pre-fill from query params (used by livetraffic Block button)
    if request.GET.get('domain'):
        rule['domain'] = request.GET.get('domain')
    if request.GET.get('ip'):
        rule['ip'] = request.GET.get('ip')
    if request.GET.get('path'):
        rule['path'] = request.GET.get('path')
    if request.GET.get('comment'):
        rule['comment'] = request.GET.get('comment')

    return render(request, 'main/global_waf_rule_form.html', {
        'rule': rule,
        'edit_mode': False,
    })


@login_required
@user_passes_test(is_superuser, login_url='/dashboard/')
def global_waf_edit_rule(request, rule_index):
    """
    Edit an existing WAF rule.
    """
    try:
        existing_rule = get_waf_rule(rule_index)
        if existing_rule is None:
            messages.error(request, f"Rule at index {rule_index} not found.")
            return redirect('global_waf_list')
    except K8sClientError as e:
        logger.error(f"Failed to get WAF rule: {e}")
        messages.error(request, f"Failed to load rule: {e}")
        return redirect('global_waf_list')

    if request.method == 'POST':
        # Build rule from form data
        rule = _build_rule_from_post(request.POST)

        # Validate rule has at least one condition
        if not rule.get('domain') and not rule.get('ip') and not rule.get('path'):
            messages.error(request, "At least one of Domain, IP, or Path is required.")
            return render(request, 'main/global_waf_rule_form.html', {
                'rule': rule,
                'rule_index': rule_index,
                'edit_mode': True,
            })

        try:
            update_waf_rule(rule_index, rule)
            messages.success(request, "WAF rule updated successfully.")
            return redirect('global_waf_list')
        except K8sClientError as e:
            logger.error(f"Failed to update WAF rule: {e}")
            messages.error(request, f"Failed to update rule: {e}")
            return render(request, 'main/global_waf_rule_form.html', {
                'rule': rule,
                'rule_index': rule_index,
                'edit_mode': True,
            })

    # GET - show form with existing rule data
    return render(request, 'main/global_waf_rule_form.html', {
        'rule': existing_rule,
        'rule_index': rule_index,
        'edit_mode': True,
    })


@login_required
@user_passes_test(is_superuser, login_url='/dashboard/')
def global_waf_delete_rule(request, rule_index):
    """
    Delete a WAF rule.
    """
    if request.method != 'POST':
        return redirect('global_waf_list')

    try:
        delete_waf_rule(rule_index)
        messages.success(request, f"WAF rule deleted successfully.")
    except K8sClientError as e:
        logger.error(f"Failed to delete WAF rule: {e}")
        messages.error(request, f"Failed to delete rule: {e}")

    return redirect('global_waf_list')


def _build_rule_from_post(post_data) -> dict:
    """
    Build a rule dict from POST form data.
    """
    rule = {}

    # Optional domain
    domain = post_data.get('domain', '').strip()
    if domain:
        rule['domain'] = domain

    # Optional IP
    ip = post_data.get('ip', '').strip()
    if ip:
        rule['ip'] = ip

    # Optional path
    path = post_data.get('path', '').strip()
    if path:
        rule['path'] = path
        # pathMatchType only relevant if path is set
        path_match_type = post_data.get('pathMatchType', 'prefix')
        if path_match_type in ('exact', 'prefix', 'regex'):
            rule['pathMatchType'] = path_match_type

    # Required action
    action = post_data.get('action', 'block')
    if action in ('block', 'allow'):
        rule['action'] = action
    else:
        rule['action'] = 'block'

    # Optional comment
    comment = post_data.get('comment', '').strip()
    if comment:
        rule['comment'] = comment

    return rule
