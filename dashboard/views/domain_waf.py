"""
Domain WAF (Web Application Firewall) views

Per-domain WAF management. Users can manage WAF rules for domains they own.
Superusers can manage WAF rules for any domain.
"""
import logging

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponseForbidden

from dashboard.models import Domain
from dashboard.k8s import (
    get_or_create_domainwaf,
    get_domainwaf,
    patch_domainwaf,
    set_domainwaf_enabled,
    add_domain_waf_rule,
    update_domain_waf_rule,
    delete_domain_waf_rule,
    get_domain_waf_rule,
    add_domain_protected_path,
    get_domain_protected_path,
    update_domain_protected_path,
    delete_domain_protected_path,
    K8sClientError,
    K8sNotFoundError,
)
from .utils import get_countries_list

logger = logging.getLogger("django")


@login_required
def domain_waf_overview(request):
    """
    Overview of all domains and their WAF status.

    Shows all domains the user owns (or all domains for superusers)
    with their WAF enabled/disabled status and rule count.
    """
    # Get user's domains (or all for superusers)
    if request.user.is_superuser:
        domains = Domain.objects.all().order_by('domain_name')
    else:
        domains = Domain.objects.filter(owner=request.user).order_by('domain_name')

    # Fetch WAF status for each domain
    domain_waf_data = []
    for domain in domains:
        waf_info = {
            'domain': domain,
            'waf_enabled': False,
            'rule_count': 0,
            'geo_enabled': False,
            'geo_count': 0,
            'phase': 'Not configured',
        }

        try:
            waf = get_domainwaf(domain.namespace)
            if waf:
                waf_info['waf_enabled'] = waf.enabled
                waf_info['rule_count'] = len(waf.rules) if waf.rules else 0
                waf_info['geo_enabled'] = waf.geo_enabled
                waf_info['geo_count'] = len(waf.blocked_countries) if waf.blocked_countries else 0
                waf_info['phase'] = waf.status.phase if waf.status else 'Unknown'
        except K8sNotFoundError:
            pass  # WAF not configured yet
        except Exception as e:
            logger.warning(f"Failed to get WAF status for {domain.domain_name}: {e}")

        domain_waf_data.append(waf_info)

    return render(request, "main/domain_waf_overview.html", {
        "domain_waf_data": domain_waf_data,
    })


def _check_domain_access(user, domain_obj):
    """
    Check if user has access to manage this domain's WAF.

    Returns None if access allowed, or HttpResponseForbidden if denied.
    """
    if user.is_superuser:
        return None
    if domain_obj.owner == user:
        return None
    return HttpResponseForbidden("You don't have permission to manage this domain's WAF.")


@login_required
def domain_waf_list(request, domain):
    """
    Display DomainWAF status and rules list.
    """
    domain_obj = get_object_or_404(Domain, domain_name=domain)

    # Authorization check
    access_denied = _check_domain_access(request.user, domain_obj)
    if access_denied:
        return access_denied

    try:
        domainwaf = get_or_create_domainwaf(domain_obj.namespace)
    except K8sClientError as e:
        logger.error(f"Failed to get DomainWAF CR for {domain}: {e}")
        messages.error(request, f"Failed to load WAF configuration: {e}")
        domainwaf = None

    # Get country list for dropdowns
    countries = get_countries_list()

    context = {
        'domain': domain_obj,
        'domainwaf': domainwaf,
        'rules': domainwaf.rules if domainwaf else [],
        'protected_paths': domainwaf.protected_paths if domainwaf else [],
        'status': domainwaf.status if domainwaf else None,
        'countries': countries,
    }
    return render(request, 'main/domain_waf.html', context)


@login_required
def domain_waf_toggle(request, domain):
    """
    Toggle DomainWAF enabled/disabled state.
    """
    if request.method != 'POST':
        return redirect('domain_waf_list', domain=domain)

    domain_obj = get_object_or_404(Domain, domain_name=domain)

    access_denied = _check_domain_access(request.user, domain_obj)
    if access_denied:
        return access_denied

    try:
        domainwaf = get_domainwaf(domain_obj.namespace)
        new_state = not domainwaf.enabled
        set_domainwaf_enabled(domain_obj.namespace, enabled=new_state)

        state_text = "enabled" if new_state else "disabled"
        messages.success(request, f"Domain WAF has been {state_text}.")
    except K8sNotFoundError:
        messages.error(request, "DomainWAF not found.")
    except K8sClientError as e:
        logger.error(f"Failed to toggle DomainWAF for {domain}: {e}")
        messages.error(request, f"Failed to toggle WAF: {e}")

    return redirect('domain_waf_list', domain=domain)


@login_required
def domain_waf_add_rule(request, domain):
    """
    Add a new WAF rule to the domain.
    """
    domain_obj = get_object_or_404(Domain, domain_name=domain)

    access_denied = _check_domain_access(request.user, domain_obj)
    if access_denied:
        return access_denied

    # Get country list for dropdown
    countries = get_countries_list()

    if request.method == 'POST':
        # Build rule from form data
        rule = _build_rule_from_post(request.POST)

        # Validate rule has at least one condition
        if not rule.get('ip') and not rule.get('path') and not rule.get('userAgent'):
            messages.error(request, "At least one of IP, Path, or User Agent is required.")
            return render(request, 'main/domain_waf_rule_form.html', {
                'domain': domain_obj,
                'rule': rule,
                'countries': countries,
                'edit_mode': False,
            })

        try:
            add_domain_waf_rule(domain_obj.namespace, rule)
            messages.success(request, "WAF rule added successfully.")
            return redirect('domain_waf_list', domain=domain)
        except K8sClientError as e:
            logger.error(f"Failed to add WAF rule for {domain}: {e}")
            messages.error(request, f"Failed to add rule: {e}")
            return render(request, 'main/domain_waf_rule_form.html', {
                'domain': domain_obj,
                'rule': rule,
                'countries': countries,
                'edit_mode': False,
            })

    # GET - show form, pre-fill from query params if provided
    rule = {
        'action': 'block',
        'pathMatchType': 'prefix',
    }

    # Pre-fill from query params (used by livetraffic Block button)
    if request.GET.get('ip'):
        rule['ip'] = request.GET.get('ip')
    if request.GET.get('path'):
        rule['path'] = request.GET.get('path')
    if request.GET.get('userAgent'):
        rule['userAgent'] = request.GET.get('userAgent')
    if request.GET.get('comment'):
        rule['comment'] = request.GET.get('comment')

    return render(request, 'main/domain_waf_rule_form.html', {
        'domain': domain_obj,
        'rule': rule,
        'countries': countries,
        'edit_mode': False,
    })


@login_required
def domain_waf_edit_rule(request, domain, rule_index):
    """
    Edit an existing WAF rule.
    """
    domain_obj = get_object_or_404(Domain, domain_name=domain)

    access_denied = _check_domain_access(request.user, domain_obj)
    if access_denied:
        return access_denied

    # Get country list for dropdown
    countries = get_countries_list()

    try:
        existing_rule = get_domain_waf_rule(domain_obj.namespace, rule_index)
        if existing_rule is None:
            messages.error(request, f"Rule at index {rule_index} not found.")
            return redirect('domain_waf_list', domain=domain)
    except K8sClientError as e:
        logger.error(f"Failed to get WAF rule for {domain}: {e}")
        messages.error(request, f"Failed to load rule: {e}")
        return redirect('domain_waf_list', domain=domain)

    if request.method == 'POST':
        # Build rule from form data
        rule = _build_rule_from_post(request.POST)

        # Validate rule has at least one condition
        if not rule.get('ip') and not rule.get('path') and not rule.get('userAgent'):
            messages.error(request, "At least one of IP, Path, or User Agent is required.")
            return render(request, 'main/domain_waf_rule_form.html', {
                'domain': domain_obj,
                'rule': rule,
                'countries': countries,
                'rule_index': rule_index,
                'edit_mode': True,
            })

        try:
            update_domain_waf_rule(domain_obj.namespace, rule_index, rule)
            messages.success(request, "WAF rule updated successfully.")
            return redirect('domain_waf_list', domain=domain)
        except K8sClientError as e:
            logger.error(f"Failed to update WAF rule for {domain}: {e}")
            messages.error(request, f"Failed to update rule: {e}")
            return render(request, 'main/domain_waf_rule_form.html', {
                'domain': domain_obj,
                'rule': rule,
                'countries': countries,
                'rule_index': rule_index,
                'edit_mode': True,
            })

    # GET - show form with existing rule data
    return render(request, 'main/domain_waf_rule_form.html', {
        'domain': domain_obj,
        'rule': existing_rule,
        'countries': countries,
        'rule_index': rule_index,
        'edit_mode': True,
    })


@login_required
def domain_waf_delete_rule(request, domain, rule_index):
    """
    Delete a WAF rule.
    """
    if request.method != 'POST':
        return redirect('domain_waf_list', domain=domain)

    domain_obj = get_object_or_404(Domain, domain_name=domain)

    access_denied = _check_domain_access(request.user, domain_obj)
    if access_denied:
        return access_denied

    try:
        delete_domain_waf_rule(domain_obj.namespace, rule_index)
        messages.success(request, "WAF rule deleted successfully.")
    except K8sClientError as e:
        logger.error(f"Failed to delete WAF rule for {domain}: {e}")
        messages.error(request, f"Failed to delete rule: {e}")

    return redirect('domain_waf_list', domain=domain)


def _build_rule_from_post(post_data) -> dict:
    """
    Build a rule dict from POST form data.
    """
    rule = {}

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

    # Optional user agent
    user_agent = post_data.get('userAgent', '').strip()
    if user_agent:
        rule['userAgent'] = user_agent

    # Optional countries - block only from these countries
    countries = post_data.getlist('countries')
    if countries:
        # Filter and uppercase
        rule['countries'] = [c.strip().upper() for c in countries if c.strip()]

    # Action is always block now (allow is removed)
    rule['action'] = 'block'

    # Optional comment
    comment = post_data.get('comment', '').strip()
    if comment:
        rule['comment'] = comment

    return rule


# =============================================================================
# Geo-blocking views
# =============================================================================

@login_required
def domain_waf_toggle_geo(request, domain):
    """
    Toggle geo-blocking enabled/disabled state.
    """
    if request.method != 'POST':
        return redirect('domain_waf_list', domain=domain)

    domain_obj = get_object_or_404(Domain, domain_name=domain)

    access_denied = _check_domain_access(request.user, domain_obj)
    if access_denied:
        return access_denied

    try:
        domainwaf = get_domainwaf(domain_obj.namespace)
        geo_block = domainwaf.geo_block or {'enabled': False, 'blockedCountries': []}
        new_state = not geo_block.get('enabled', False)

        patch_domainwaf(
            namespace=domain_obj.namespace,
            geo_block={
                'enabled': new_state,
                'blockedCountries': geo_block.get('blockedCountries', [])
            }
        )

        state_text = "enabled" if new_state else "disabled"
        messages.success(request, f"Geo-blocking has been {state_text}.")
    except K8sNotFoundError:
        messages.error(request, "DomainWAF not found.")
    except K8sClientError as e:
        logger.error(f"Failed to toggle geo-blocking for {domain}: {e}")
        messages.error(request, f"Failed to toggle geo-blocking: {e}")

    return redirect('domain_waf_list', domain=domain)


@login_required
def domain_waf_add_country(request, domain):
    """
    Add a country to the geo-block list.
    """
    if request.method != 'POST':
        return redirect('domain_waf_list', domain=domain)

    domain_obj = get_object_or_404(Domain, domain_name=domain)

    access_denied = _check_domain_access(request.user, domain_obj)
    if access_denied:
        return access_denied

    country_code = request.POST.get('country_code', '').strip().upper()
    if not country_code or len(country_code) != 2:
        messages.error(request, "Invalid country code. Must be 2-letter ISO code.")
        return redirect('domain_waf_list', domain=domain)

    try:
        domainwaf = get_domainwaf(domain_obj.namespace)
        geo_block = domainwaf.geo_block or {'enabled': False, 'blockedCountries': []}
        blocked_countries = geo_block.get('blockedCountries', [])

        if country_code in blocked_countries:
            messages.warning(request, f"Country {country_code} is already blocked.")
            return redirect('domain_waf_list', domain=domain)

        blocked_countries.append(country_code)

        patch_domainwaf(
            namespace=domain_obj.namespace,
            geo_block={
                'enabled': geo_block.get('enabled', False),
                'blockedCountries': blocked_countries
            }
        )

        messages.success(request, f"Country {country_code} added to block list.")
    except K8sNotFoundError:
        messages.error(request, "DomainWAF not found.")
    except K8sClientError as e:
        logger.error(f"Failed to add country for {domain}: {e}")
        messages.error(request, f"Failed to add country: {e}")

    return redirect('domain_waf_list', domain=domain)


@login_required
def domain_waf_remove_country(request, domain, country_code):
    """
    Remove a country from the geo-block list.
    """
    if request.method != 'POST':
        return redirect('domain_waf_list', domain=domain)

    domain_obj = get_object_or_404(Domain, domain_name=domain)

    access_denied = _check_domain_access(request.user, domain_obj)
    if access_denied:
        return access_denied

    country_code = country_code.upper()

    try:
        domainwaf = get_domainwaf(domain_obj.namespace)
        geo_block = domainwaf.geo_block or {'enabled': False, 'blockedCountries': []}
        blocked_countries = geo_block.get('blockedCountries', [])

        if country_code not in blocked_countries:
            messages.warning(request, f"Country {country_code} is not in block list.")
            return redirect('domain_waf_list', domain=domain)

        blocked_countries.remove(country_code)

        patch_domainwaf(
            namespace=domain_obj.namespace,
            geo_block={
                'enabled': geo_block.get('enabled', False),
                'blockedCountries': blocked_countries
            }
        )

        messages.success(request, f"Country {country_code} removed from block list.")
    except K8sNotFoundError:
        messages.error(request, "DomainWAF not found.")
    except K8sClientError as e:
        logger.error(f"Failed to remove country for {domain}: {e}")
        messages.error(request, f"Failed to remove country: {e}")

    return redirect('domain_waf_list', domain=domain)


# =============================================================================
# Protected Paths views
# =============================================================================

@login_required
def domain_waf_add_protected_path(request, domain):
    """
    Add a protected path (allowlist).
    """
    if request.method != 'POST':
        return redirect('domain_waf_list', domain=domain)

    domain_obj = get_object_or_404(Domain, domain_name=domain)

    access_denied = _check_domain_access(request.user, domain_obj)
    if access_denied:
        return access_denied

    # Build protected path from form data
    path = request.POST.get('path', '').strip()
    if not path:
        messages.error(request, "Path is required.")
        return redirect('domain_waf_list', domain=domain)

    path_match_type = request.POST.get('pathMatchType', 'prefix')
    if path_match_type not in ('exact', 'prefix', 'regex'):
        path_match_type = 'prefix'

    allow_type = request.POST.get('allow_type', 'ip')
    comment = request.POST.get('comment', '').strip()

    protected_path = {
        'path': path,
        'pathMatchType': path_match_type,
    }

    if allow_type == 'ip':
        allowed_ip = request.POST.get('allowedIp', '').strip()
        if not allowed_ip:
            messages.error(request, "IP address is required when using IP allowlist.")
            return redirect('domain_waf_list', domain=domain)
        protected_path['allowedIp'] = allowed_ip
    else:
        allowed_countries = request.POST.getlist('allowedCountries')
        if not allowed_countries:
            messages.error(request, "At least one country is required when using country allowlist.")
            return redirect('domain_waf_list', domain=domain)
        protected_path['allowedCountries'] = [c.strip().upper() for c in allowed_countries if c.strip()]

    if comment:
        protected_path['comment'] = comment

    try:
        add_domain_protected_path(domain_obj.namespace, protected_path)
        messages.success(request, f"Protected path '{path}' added successfully.")
    except K8sClientError as e:
        logger.error(f"Failed to add protected path for {domain}: {e}")
        messages.error(request, f"Failed to add protected path: {e}")

    return redirect('domain_waf_list', domain=domain)


@login_required
def domain_waf_delete_protected_path(request, domain, path_index):
    """
    Delete a protected path.
    """
    if request.method != 'POST':
        return redirect('domain_waf_list', domain=domain)

    domain_obj = get_object_or_404(Domain, domain_name=domain)

    access_denied = _check_domain_access(request.user, domain_obj)
    if access_denied:
        return access_denied

    try:
        delete_domain_protected_path(domain_obj.namespace, path_index)
        messages.success(request, "Protected path deleted successfully.")
    except K8sClientError as e:
        logger.error(f"Failed to delete protected path for {domain}: {e}")
        messages.error(request, f"Failed to delete protected path: {e}")

    return redirect('domain_waf_list', domain=domain)


@login_required
def domain_waf_edit_protected_path(request, domain, path_index):
    """
    Edit a protected path.
    """
    domain_obj = get_object_or_404(Domain, domain_name=domain)

    access_denied = _check_domain_access(request.user, domain_obj)
    if access_denied:
        return access_denied

    # Get country list for dropdowns
    countries = get_countries_list()

    try:
        existing_path = get_domain_protected_path(domain_obj.namespace, path_index)
        if existing_path is None:
            messages.error(request, f"Protected path at index {path_index} not found.")
            return redirect('domain_waf_list', domain=domain)
    except K8sClientError as e:
        logger.error(f"Failed to get protected path for {domain}: {e}")
        messages.error(request, f"Failed to load protected path: {e}")
        return redirect('domain_waf_list', domain=domain)

    if request.method == 'POST':
        # Build protected path from form data
        path = request.POST.get('path', '').strip()
        if not path:
            messages.error(request, "Path is required.")
            return render(request, 'main/domain_waf_edit_path.html', {
                'domain': domain_obj,
                'path_index': path_index,
                'protected_path': existing_path,
                'countries': countries,
            })

        path_match_type = request.POST.get('pathMatchType', 'prefix')
        if path_match_type not in ('exact', 'prefix', 'regex'):
            path_match_type = 'prefix'

        allow_type = request.POST.get('allow_type', 'ip')
        comment = request.POST.get('comment', '').strip()

        protected_path = {
            'path': path,
            'pathMatchType': path_match_type,
        }

        if allow_type == 'ip':
            allowed_ip = request.POST.get('allowedIp', '').strip()
            if not allowed_ip:
                messages.error(request, "IP address is required when using IP allowlist.")
                return render(request, 'main/domain_waf_edit_path.html', {
                    'domain': domain_obj,
                    'path_index': path_index,
                    'protected_path': existing_path,
                    'countries': countries,
                })
            protected_path['allowedIp'] = allowed_ip
        else:
            allowed_countries = request.POST.getlist('allowedCountries')
            if not allowed_countries:
                messages.error(request, "At least one country is required when using country allowlist.")
                return render(request, 'main/domain_waf_edit_path.html', {
                    'domain': domain_obj,
                    'path_index': path_index,
                    'protected_path': existing_path,
                    'countries': countries,
                })
            protected_path['allowedCountries'] = [c.strip().upper() for c in allowed_countries if c.strip()]

        if comment:
            protected_path['comment'] = comment

        try:
            update_domain_protected_path(domain_obj.namespace, path_index, protected_path)
            messages.success(request, f"Protected path '{path}' updated successfully.")
            return redirect('domain_waf_list', domain=domain)
        except K8sClientError as e:
            logger.error(f"Failed to update protected path for {domain}: {e}")
            messages.error(request, f"Failed to update protected path: {e}")
            return render(request, 'main/domain_waf_edit_path.html', {
                'domain': domain_obj,
                'path_index': path_index,
                'protected_path': existing_path,
                'countries': countries,
            })

    # GET - show form with existing protected path data
    return render(request, 'main/domain_waf_edit_path.html', {
        'domain': domain_obj,
        'path_index': path_index,
        'protected_path': existing_path,
        'countries': countries,
    })
