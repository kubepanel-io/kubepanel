"""
L3 Firewall (Network-level) views

Admin-only views for managing GlobalL3Firewall rules using Calico GlobalNetworkPolicy.
"""
import logging

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages

from dashboard.k8s import (
    get_or_create_l3_firewall,
    get_l3_firewall,
    set_l3_firewall_enabled,
    add_l3_rule,
    update_l3_rule,
    delete_l3_rule,
    get_l3_rule,
    K8sClientError,
    K8sNotFoundError,
)

logger = logging.getLogger("django")


def is_superuser(user):
    """Check if user is superuser (admin)."""
    return user.is_superuser


@login_required
@user_passes_test(is_superuser, login_url='/dashboard/')
def l3_firewall_list(request):
    """
    Display L3 Firewall status and rules list.

    Admin only - shows all L3 firewall rules with enable/disable toggle.
    """
    try:
        l3_firewall = get_or_create_l3_firewall()
    except K8sClientError as e:
        logger.error(f"Failed to get GlobalL3Firewall CR: {e}")
        messages.error(request, f"Failed to load L3 Firewall configuration: {e}")
        l3_firewall = None

    context = {
        'l3_firewall': l3_firewall,
        'rules': l3_firewall.rules if l3_firewall else [],
        'status': l3_firewall.status if l3_firewall else None,
    }
    return render(request, 'main/l3_firewall.html', context)


@login_required
@user_passes_test(is_superuser, login_url='/dashboard/')
def l3_firewall_toggle(request):
    """
    Toggle L3 Firewall enabled/disabled state.
    """
    if request.method != 'POST':
        return redirect('l3_firewall_list')

    try:
        l3_firewall = get_l3_firewall()
        new_state = not l3_firewall.enabled
        set_l3_firewall_enabled(enabled=new_state)

        state_text = "enabled" if new_state else "disabled"
        messages.success(request, f"L3 Firewall has been {state_text}.")
    except K8sNotFoundError:
        messages.error(request, "GlobalL3Firewall CR not found.")
    except K8sClientError as e:
        logger.error(f"Failed to toggle L3 Firewall: {e}")
        messages.error(request, f"Failed to toggle L3 Firewall: {e}")

    return redirect('l3_firewall_list')


@login_required
@user_passes_test(is_superuser, login_url='/dashboard/')
def l3_firewall_add_rule(request):
    """
    Add a new L3 firewall rule.
    """
    if request.method == 'POST':
        # Build rule from form data
        rule = _build_l3_rule_from_post(request.POST)

        # Validate rule has at least source or destination
        if not rule.get('source') and not rule.get('destination'):
            messages.error(request, "At least one of Source CIDRs or Destination Ports is required.")
            return render(request, 'main/l3_firewall_rule_form.html', {
                'rule': rule,
                'edit_mode': False,
            })

        try:
            add_l3_rule(rule)
            messages.success(request, "L3 Firewall rule added successfully.")
            return redirect('l3_firewall_list')
        except K8sClientError as e:
            logger.error(f"Failed to add L3 Firewall rule: {e}")
            messages.error(request, f"Failed to add rule: {e}")
            return render(request, 'main/l3_firewall_rule_form.html', {
                'rule': rule,
                'edit_mode': False,
            })

    # GET - show form, pre-fill from query params if provided
    rule = {
        'name': '',
        'action': 'deny',
        'protocol': 'TCP',
    }

    # Pre-fill from query params (used by livetraffic Block button)
    if request.GET.get('ip'):
        ip = request.GET.get('ip')
        # Normalize IP to CIDR if it's a single IP
        if '/' not in ip:
            ip = f"{ip}/32"
        rule['source_cidrs'] = ip
    if request.GET.get('comment'):
        rule['name'] = request.GET.get('comment')

    return render(request, 'main/l3_firewall_rule_form.html', {
        'rule': rule,
        'edit_mode': False,
    })


@login_required
@user_passes_test(is_superuser, login_url='/dashboard/')
def l3_firewall_edit_rule(request, rule_index):
    """
    Edit an existing L3 firewall rule.
    """
    try:
        existing_rule = get_l3_rule(rule_index)
        if existing_rule is None:
            messages.error(request, f"Rule at index {rule_index} not found.")
            return redirect('l3_firewall_list')
    except K8sClientError as e:
        logger.error(f"Failed to get L3 Firewall rule: {e}")
        messages.error(request, f"Failed to load rule: {e}")
        return redirect('l3_firewall_list')

    if request.method == 'POST':
        # Build rule from form data
        rule = _build_l3_rule_from_post(request.POST)

        # Validate rule has at least source or destination
        if not rule.get('source') and not rule.get('destination'):
            messages.error(request, "At least one of Source CIDRs or Destination Ports is required.")
            return render(request, 'main/l3_firewall_rule_form.html', {
                'rule': rule,
                'rule_index': rule_index,
                'edit_mode': True,
            })

        try:
            update_l3_rule(rule_index, rule)
            messages.success(request, "L3 Firewall rule updated successfully.")
            return redirect('l3_firewall_list')
        except K8sClientError as e:
            logger.error(f"Failed to update L3 Firewall rule: {e}")
            messages.error(request, f"Failed to update rule: {e}")
            return render(request, 'main/l3_firewall_rule_form.html', {
                'rule': rule,
                'rule_index': rule_index,
                'edit_mode': True,
            })

    # GET - show form with existing rule data
    # Flatten the rule for easier form handling
    flat_rule = _flatten_rule_for_form(existing_rule)

    return render(request, 'main/l3_firewall_rule_form.html', {
        'rule': flat_rule,
        'rule_index': rule_index,
        'edit_mode': True,
    })


@login_required
@user_passes_test(is_superuser, login_url='/dashboard/')
def l3_firewall_delete_rule(request, rule_index):
    """
    Delete an L3 firewall rule.
    """
    if request.method != 'POST':
        return redirect('l3_firewall_list')

    try:
        delete_l3_rule(rule_index)
        messages.success(request, f"L3 Firewall rule deleted successfully.")
    except K8sClientError as e:
        logger.error(f"Failed to delete L3 Firewall rule: {e}")
        messages.error(request, f"Failed to delete rule: {e}")

    return redirect('l3_firewall_list')


def _build_l3_rule_from_post(post_data) -> dict:
    """
    Build an L3 rule dict from POST form data.
    """
    rule = {}

    # Required name
    name = post_data.get('name', '').strip()
    if name:
        rule['name'] = name
    else:
        rule['name'] = 'Unnamed Rule'

    # Required action
    action = post_data.get('action', 'deny')
    if action in ('deny', 'allow'):
        rule['action'] = action
    else:
        rule['action'] = 'deny'

    # Protocol
    protocol = post_data.get('protocol', 'TCP')
    if protocol in ('TCP', 'UDP'):
        rule['protocol'] = protocol
    else:
        rule['protocol'] = 'TCP'

    # Source networks
    source_nets = post_data.get('source_nets', '').strip()
    source_not_nets = post_data.get('source_not_nets', '').strip()

    if source_nets:
        # Split by comma or newline and clean
        nets = [n.strip() for n in source_nets.replace('\n', ',').split(',') if n.strip()]
        if nets:
            rule['source'] = {'nets': nets}
    elif source_not_nets:
        # notNets - inverse match (block everything except these)
        nets = [n.strip() for n in source_not_nets.replace('\n', ',').split(',') if n.strip()]
        if nets:
            rule['source'] = {'notNets': nets}

    # Destination ports
    dest_ports = post_data.get('destination_ports', '').strip()
    if dest_ports:
        # Parse ports - can be comma separated
        try:
            ports = [int(p.strip()) for p in dest_ports.split(',') if p.strip()]
            if ports:
                rule['destination'] = {'ports': ports}
        except ValueError:
            # Invalid port number, skip
            pass

    return rule


def _flatten_rule_for_form(rule: dict) -> dict:
    """
    Flatten a rule dict for easier form population.
    """
    flat = {
        'name': rule.get('name', ''),
        'action': rule.get('action', 'deny'),
        'protocol': rule.get('protocol', 'TCP'),
        'source_nets': '',
        'source_not_nets': '',
        'destination_ports': '',
    }

    # Flatten source
    source = rule.get('source', {})
    if source.get('nets'):
        flat['source_nets'] = ', '.join(source['nets'])
    elif source.get('notNets'):
        flat['source_not_nets'] = ', '.join(source['notNets'])

    # Flatten destination
    destination = rule.get('destination', {})
    if destination.get('ports'):
        flat['destination_ports'] = ', '.join(str(p) for p in destination['ports'])

    return flat
