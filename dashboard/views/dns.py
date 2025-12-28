"""
DNS and Cloudflare API management views
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db import transaction

import json
import logging

from dashboard.models import DNSZone, DNSRecord, CloudflareAPIToken, Domain
from dashboard.forms import APITokenForm, ZoneCreationForm, DNSRecordForm
from dashboard.services.dns_service import (
    CloudflareDNSService,
    DNSZoneManager,
    DNSRecordData,
    CloudflareAPIException,
)
from dashboard.k8s import (
    get_domain as k8s_get_domain,
    add_dns_record as k8s_add_dns_record,
    update_dns_record as k8s_update_dns_record,
    delete_dns_record_from_cr as k8s_delete_dns_record,
    K8sNotFoundError,
    K8sClientError,
)

logger = logging.getLogger("django")


def zones_list(request):
    tokens = CloudflareAPIToken.objects.filter(user=request.user)
    user_zones = DNSZone.objects.filter(token__in=tokens)
    return render(request, "main/zones_list.html", {"zones": user_zones})


def create_zone(request):
    """Create a DNS zone"""
    if request.method == "POST":
        form = ZoneCreationForm(request.user, request.POST)
        if form.is_valid():
            zone_name = form.cleaned_data["zone_name"]
            user_token = form.cleaned_data["token"]

            try:
                zone_manager = DNSZoneManager(user_token)
                zone_obj, _ = zone_manager.create_zone_with_records(zone_name, [])
                messages.success(request, f"Zone '{zone_name}' created successfully.")

            except CloudflareAPIException as e:
                logger.error(f"Cloudflare API error creating zone: {e}")
                messages.error(request, f"Failed to create zone: {e.message}")
            except Exception as e:
                logger.error(f"Unexpected error creating zone: {e}")
                messages.error(request, "An unexpected error occurred. Please try again.")

            return redirect("zones_list")
    else:
        form = ZoneCreationForm(request.user)

    return render(request, "main/create_zone.html", {"form": form})


def delete_zone(request, zone_id):
    """Delete DNS zone from both Cloudflare and database"""
    zone = get_object_or_404(DNSZone, id=zone_id, token__user=request.user)

    record_count = zone.dns_records.count()
    has_records = record_count > 0

    if request.method == "POST":
        if has_records:
            messages.error(request, f"Cannot delete zone '{zone.name}' because it contains {record_count} DNS record(s). Please delete all records first.")
            return redirect("list_dns_records", zone_id=zone.id)

        try:
            zone_name = zone.name

            try:
                dns_service = CloudflareDNSService(zone.token.api_token)
                dns_service._retry_api_call(
                    dns_service.client.zones.delete,
                    zone_id=zone.zone_id
                )
                logger.info(f"Successfully deleted zone {zone_name} from Cloudflare")
            except CloudflareAPIException as e:
                logger.error(f"Failed to delete zone from Cloudflare: {e}")
                messages.error(request, f"Failed to delete zone from Cloudflare: {e.message}")
                return redirect("zones_list")
            except Exception as e:
                logger.error(f"Unexpected error deleting zone from Cloudflare: {e}")
                messages.error(request, f"Failed to delete zone from Cloudflare: {str(e)}")
                return redirect("zones_list")

            zone.delete()
            messages.success(request, f"DNS Zone '{zone_name}' deleted successfully.")
            logger.info(f"User {request.user.username} deleted DNS zone {zone_name}")

            return redirect("zones_list")

        except Exception as e:
            logger.error(f"Error deleting zone: {e}")
            messages.error(request, f"Error deleting zone: {e}")
            return redirect("zones_list")

    return render(request, "main/delete_zone_confirm.html", {
        "zone": zone,
        "has_records": has_records,
        "record_count": record_count,
        "type": "DNS Zone"
    })


def list_dns_records(request, zone_id):
    zone = get_object_or_404(DNSZone, pk=zone_id)
    records = zone.dns_records.all()
    return render(request, "main/list_dns_records.html", {"zone": zone, "records": records})


def create_dns_record(request):
    """Create a single DNS record"""
    zone_id = request.GET.get('zone')
    zone = None

    if zone_id:
        zone = get_object_or_404(DNSZone, id=zone_id)

    if request.method == "POST":
        form = DNSRecordForm(request.POST, user=request.user)

        if zone and 'zone' not in request.POST:
            post_data = request.POST.copy()
            post_data['zone'] = zone.id
            form = DNSRecordForm(post_data, user=request.user)

        logger.info(f"Form data: {request.POST}")
        logger.info(f"Zone from URL: {zone}")

        if form.is_valid():
            logger.info(f"Form cleaned data: {form.cleaned_data}")

            try:
                record_obj = form.save(commit=False)

                if zone:
                    record_obj.zone = zone

                logger.info(f"Creating record: {record_obj.record_type} {record_obj.name} -> {record_obj.content}")
                logger.info(f"Zone: {record_obj.zone}")

                dns_service = CloudflareDNSService(record_obj.zone.token.api_token)
                record_data = DNSRecordData(
                    record_type=record_obj.record_type,
                    name=record_obj.name,
                    content=record_obj.content,
                    ttl=record_obj.ttl,
                    proxied=record_obj.proxied,
                    priority=record_obj.priority
                )

                with transaction.atomic():
                    cf_record = dns_service.create_dns_record(record_obj.zone.zone_id, record_data)

                    if hasattr(cf_record, 'id'):
                        record_obj.cf_record_id = cf_record.id
                    elif isinstance(cf_record, dict) and 'id' in cf_record:
                        record_obj.cf_record_id = cf_record['id']
                    else:
                        logger.error(f"Unexpected Cloudflare response format: {cf_record}")
                        raise ValueError("Could not extract record ID from Cloudflare response")

                    record_obj.save()
                    logger.info(f"DNS record saved with ID: {record_obj.id}, CF ID: {record_obj.cf_record_id}")

                messages.success(request, "DNS record created successfully.")
                return redirect("list_dns_records", zone_id=record_obj.zone.id)

            except CloudflareAPIException as e:
                logger.error(f"Cloudflare API error: {e}")
                messages.error(request, f"Cloudflare API error: {str(e)}")
            except Exception as e:
                logger.error(f"Unexpected error creating DNS record: {e}", exc_info=True)
                messages.error(request, "An unexpected error occurred. Please try again.")
        else:
            logger.error(f"Form errors: {form.errors}")
            messages.error(request, "Please correct the form errors.")
    else:
        initial_data = {}
        if zone:
            initial_data['zone'] = zone.id

        form = DNSRecordForm(user=request.user, initial=initial_data)

    return render(request, "main/create_dns_record.html", {
        "form": form,
        "zone": zone,
        "zone_id": zone_id
    })


def edit_dns_record(request, record_id):
    """Edit an existing DNS record"""
    logger.info(f"Starting edit_dns_record for record_id: {record_id}")

    try:
        record = get_object_or_404(DNSRecord, id=record_id)
        zone = record.zone
        logger.info(f"Found record: {record.record_type} {record.name} -> {record.content}")

    except Exception as e:
        logger.error(f"Error getting record: {e}")
        messages.error(request, f"Record not found: {e}")
        return redirect("zones_list")

    if request.method == "POST":
        logger.info("Processing POST request")
        logger.info(f"POST data: {dict(request.POST)}")

        form = DNSRecordForm(request.POST, instance=record, user=request.user)

        if form.is_valid():
            logger.info("Form is valid")
            logger.info(f"Form cleaned data: {form.cleaned_data}")

            try:
                updated_record = form.save(commit=False)
                updated_record.zone = record.zone
                updated_record.cf_record_id = record.cf_record_id

                logger.info(f"Updated record prepared: {updated_record.record_type} {updated_record.name} -> {updated_record.content}")

                dns_service = CloudflareDNSService(record.zone.token.api_token)
                logger.info("Cloudflare service initialized")

                update_params = {
                    'zone_id': record.zone.zone_id,
                    'dns_record_id': record.cf_record_id,
                    'type': updated_record.record_type,
                    'name': updated_record.name,
                    'content': updated_record.content,
                    'ttl': updated_record.ttl,
                    'proxied': updated_record.proxied,
                }

                if updated_record.priority is not None and updated_record.record_type in ['MX', 'SRV']:
                    update_params['priority'] = updated_record.priority

                logger.info(f"Cloudflare update parameters: {update_params}")

                try:
                    logger.info("Attempting Cloudflare update...")
                    cf_response = dns_service._retry_api_call(
                        dns_service.client.dns.records.update,
                        **update_params
                    )
                    logger.info(f"Cloudflare update successful: {type(cf_response)}")

                except Exception as cf_error:
                    logger.error(f"Cloudflare update failed: {cf_error}")
                    logger.error(f"Error type: {type(cf_error)}")

                    logger.info("Trying delete + create approach...")

                    try:
                        logger.info(f"Deleting old record: {record.cf_record_id}")
                        dns_service._retry_api_call(
                            dns_service.client.dns.records.delete,
                            zone_id=record.zone.zone_id,
                            dns_record_id=record.cf_record_id
                        )
                        logger.info("Old record deleted")

                        record_data = DNSRecordData(
                            record_type=updated_record.record_type,
                            name=updated_record.name,
                            content=updated_record.content,
                            ttl=updated_record.ttl,
                            proxied=updated_record.proxied,
                            priority=updated_record.priority
                        )
                        logger.info(f"Creating new record: {record_data}")

                        cf_record = dns_service.create_dns_record(record.zone.zone_id, record_data)
                        logger.info(f"New record created")

                        record_id_new = cf_record.id if hasattr(cf_record, 'id') else cf_record.get('id')
                        updated_record.cf_record_id = record_id_new
                        logger.info(f"New Cloudflare record ID: {record_id_new}")

                    except Exception as fallback_error:
                        logger.error(f"Fallback approach failed: {fallback_error}")
                        raise fallback_error

                logger.info("Saving to database...")
                with transaction.atomic():
                    updated_record.save()
                    logger.info("Database save successful")

                messages.success(request, "DNS record updated successfully.")
                logger.info("Edit completed successfully")
                return redirect("list_dns_records", zone_id=zone.id)

            except CloudflareAPIException as e:
                logger.error(f"CloudflareAPIException: {e}")
                messages.error(request, f"Cloudflare API error: {e.message}")

            except Exception as e:
                logger.error(f"Unexpected error: {e}", exc_info=True)
                messages.error(request, f"An unexpected error occurred: {str(e)}")

        else:
            logger.error(f"Form is not valid. Errors: {form.errors}")
            messages.error(request, "Please correct the form errors.")
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        logger.info("GET request - displaying form")
        form = DNSRecordForm(instance=record, user=request.user)

    return render(request, "main/edit_dns_record.html", {
        "form": form,
        "record": record,
        "zone": zone,
    })


def delete_dns_record(request, record_id):
    """Delete DNS record from both Cloudflare and database"""
    record = get_object_or_404(DNSRecord, id=record_id, zone__token__user=request.user)

    if request.method == "POST":
        try:
            record_name = record.name
            record_type = record.record_type

            dns_service = CloudflareDNSService(record.zone.token.api_token)

            if record.cf_record_id:
                try:
                    dns_service._retry_api_call(
                        dns_service.client.dns.records.delete,
                        zone_id=record.zone.zone_id,
                        dns_record_id=record.cf_record_id
                    )
                    logger.info(f"Successfully deleted DNS record {record_name} from Cloudflare")
                except CloudflareAPIException as e:
                    logger.error(f"Failed to delete from Cloudflare: {e}")
                    messages.error(request, f"Failed to delete from Cloudflare: {e.message}")
                    return redirect("list_dns_records", zone_id=record.zone.id)
                except Exception as e:
                    logger.error(f"Unexpected Cloudflare error: {e}")
                    messages.error(request, f"Failed to delete from Cloudflare: {str(e)}")
                    return redirect("list_dns_records", zone_id=record.zone.id)

            zone_id = record.zone.id
            record.delete()

            messages.success(request, f'DNS record "{record_name}" ({record_type}) deleted successfully.')
            return redirect("list_dns_records", zone_id=zone_id)

        except Exception as e:
            logger.error(f"Error deleting DNS record: {e}")
            messages.error(request, f"Error deleting record: {e}")
            return redirect("list_dns_records", zone_id=record.zone.id)

    return render(request, "main/delete_dns_record_confirm.html", {
        "record": record,
        "zone": record.zone,
        "type": "DNS Record"
    })


@login_required
def bulk_delete_dns_records(request):
    """Delete multiple DNS records at once via AJAX"""
    if request.method != "POST":
        return JsonResponse({'status': 'error', 'message': 'Method not allowed'}, status=405)

    try:
        data = json.loads(request.body)
        record_ids = data.get('record_ids', [])

        if not record_ids:
            return JsonResponse({
                'status': 'error',
                'message': 'No records selected for deletion.'
            }, status=400)

        dns_records = DNSRecord.objects.filter(
            id__in=record_ids,
            zone__token__user=request.user
        ).select_related('zone', 'zone__token')

        if not dns_records.exists():
            return JsonResponse({
                'status': 'error',
                'message': 'No valid records found for deletion.'
            }, status=404)

        deleted_count = 0
        failed_count = 0
        failed_records = []

        zones = {}
        for record in dns_records:
            if record.zone.id not in zones:
                zones[record.zone.id] = {
                    'dns_service': CloudflareDNSService(record.zone.token.api_token),
                    'zone_id': record.zone.zone_id,
                    'records': []
                }
            zones[record.zone.id]['records'].append(record)

        for zone_data in zones.values():
            dns_service = zone_data['dns_service']
            zone_id = zone_data['zone_id']

            for record in zone_data['records']:
                try:
                    if record.cf_record_id:
                        dns_service._retry_api_call(
                            dns_service.client.dns.records.delete,
                            zone_id=zone_id,
                            dns_record_id=record.cf_record_id
                        )

                    record.delete()
                    deleted_count += 1

                except Exception as e:
                    logger.error(f"Failed to delete record {record.name}: {e}")
                    failed_count += 1
                    failed_records.append(f"{record.name} ({record.record_type})")

        if failed_count == 0:
            return JsonResponse({
                'status': 'success',
                'message': f'Successfully deleted {deleted_count} DNS records.'
            })
        elif deleted_count > 0:
            return JsonResponse({
                'status': 'partial',
                'message': f'Deleted {deleted_count} records. Failed: {", ".join(failed_records)}'
            })
        else:
            return JsonResponse({
                'status': 'error',
                'message': f'Failed to delete any records. Errors: {", ".join(failed_records)}'
            }, status=500)

    except json.JSONDecodeError:
        return JsonResponse({
            'status': 'error',
            'message': 'Invalid JSON data.'
        }, status=400)
    except Exception as e:
        logger.error(f"Bulk delete error: {e}")
        return JsonResponse({
            'status': 'error',
            'message': f'An error occurred: {str(e)}'
        }, status=500)


# API Token management
def add_api_token(request):
    if request.method == "POST":
        form = APITokenForm(request.POST)
        if form.is_valid():
            token_obj = form.save(commit=False)
            token_obj.user = request.user
            token_obj.save()
            return redirect("list_api_tokens")
    else:
        form = APITokenForm()
    return render(request, "main/add_token.html", {"form": form})


def list_api_tokens(request):
    tokens = CloudflareAPIToken.objects.filter(user=request.user)
    return render(request, "main/list_api_tokens.html", {"tokens": tokens})


def delete_api_token(request, token_id):
    token = get_object_or_404(CloudflareAPIToken, id=token_id, user=request.user)
    if request.method == "POST":
        try:
            token.delete()
            messages.success(request, f"API Token '{token.name}' deleted successfully.")
        except Exception as e:
            messages.error(request, f"Error deleting token: {e}")
        return redirect("list_api_tokens")
    return render(request, "main/delete_confirm.html", {"object": token, "type": "API Token"})


# =============================================================================
# Domain-centric DNS management (via Domain CR)
# =============================================================================

@login_required
def domain_dns_records(request, domain):
    """List DNS records from Domain CR status."""
    domain_obj = get_object_or_404(Domain, domain_name=domain)

    try:
        k8s_domain = k8s_get_domain(domain)
        dns_spec = k8s_domain.spec.get('dns', {})
        dns_status = k8s_domain.status._raw.get('dns', {}) if k8s_domain.status else {}

        # Get records from spec (what we want) and status (what CF has)
        spec_records = dns_spec.get('records', [])
        status_records = dns_status.get('records', [])

        # Merge status info with spec records (for display)
        records = []
        for i, record in enumerate(spec_records):
            record_display = {
                'index': i,
                'type': record.get('type', ''),
                'name': record.get('name', ''),
                'content': record.get('content', ''),
                'ttl': record.get('ttl', 1),
                'proxied': record.get('proxied', False),
                'priority': record.get('priority'),
            }
            # Try to find matching status record for CF ID and status
            for status_rec in status_records:
                if (status_rec.get('type') == record.get('type') and
                    status_rec.get('name') == record.get('name') and
                    status_rec.get('content') == record.get('content')):
                    record_display['cf_record_id'] = status_rec.get('recordId')
                    record_display['status'] = status_rec.get('status', 'Unknown')
                    break
            else:
                record_display['status'] = 'Pending'
            records.append(record_display)

        zone = dns_status.get('zone', {})
        dns_enabled = dns_spec.get('enabled', False)

    except K8sNotFoundError:
        messages.error(request, f"Domain CR not found for {domain}")
        return redirect('kpmain')
    except K8sClientError as e:
        messages.error(request, f"Error fetching domain: {e}")
        return redirect('kpmain')

    return render(request, 'main/domain_dns_records.html', {
        'domain': domain_obj,
        'domain_name': domain,
        'zone': zone,
        'records': records,
        'dns_phase': dns_status.get('phase'),
        'dns_enabled': dns_enabled,
    })


@login_required
def add_domain_dns_record(request, domain):
    """Add DNS record by patching Domain CR spec."""
    domain_obj = get_object_or_404(Domain, domain_name=domain)

    if request.method == 'POST':
        record_type = request.POST.get('record_type', 'A')
        name = request.POST.get('name', '@')
        content = request.POST.get('content', '')
        ttl = int(request.POST.get('ttl', 1))
        proxied = request.POST.get('proxied') == 'on'
        priority = request.POST.get('priority')

        new_record = {
            'type': record_type,
            'name': name,
            'content': content,
            'ttl': ttl,
            'proxied': proxied,
        }
        if priority and record_type in ['MX', 'SRV']:
            new_record['priority'] = int(priority)

        try:
            k8s_add_dns_record(domain, new_record)
            messages.success(request, f"DNS record added. It may take a moment to propagate to Cloudflare.")
            return redirect('domain_dns_records', domain=domain)
        except K8sClientError as e:
            messages.error(request, f"Failed to add DNS record: {e}")

    return render(request, 'main/add_domain_dns_record.html', {
        'domain': domain_obj,
        'domain_name': domain,
        'record_types': ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'CAA'],
    })


@login_required
def edit_domain_dns_record(request, domain, record_index):
    """Edit DNS record by patching Domain CR spec."""
    domain_obj = get_object_or_404(Domain, domain_name=domain)

    try:
        k8s_domain = k8s_get_domain(domain)
        dns_spec = k8s_domain.spec.get('dns', {})
        records = dns_spec.get('records', [])

        if record_index < 0 or record_index >= len(records):
            messages.error(request, "Record not found.")
            return redirect('domain_dns_records', domain=domain)

        record = records[record_index]

    except K8sNotFoundError:
        messages.error(request, f"Domain CR not found for {domain}")
        return redirect('kpmain')
    except K8sClientError as e:
        messages.error(request, f"Error fetching domain: {e}")
        return redirect('kpmain')

    if request.method == 'POST':
        record_type = request.POST.get('record_type', record.get('type', 'A'))
        name = request.POST.get('name', record.get('name', '@'))
        content = request.POST.get('content', record.get('content', ''))
        ttl = int(request.POST.get('ttl', record.get('ttl', 1)))
        proxied = request.POST.get('proxied') == 'on'
        priority = request.POST.get('priority')

        updated_record = {
            'type': record_type,
            'name': name,
            'content': content,
            'ttl': ttl,
            'proxied': proxied,
        }
        if priority and record_type in ['MX', 'SRV']:
            updated_record['priority'] = int(priority)

        try:
            k8s_update_dns_record(domain, record_index, updated_record)
            messages.success(request, f"DNS record updated. It may take a moment to propagate to Cloudflare.")
            return redirect('domain_dns_records', domain=domain)
        except K8sClientError as e:
            messages.error(request, f"Failed to update DNS record: {e}")

    return render(request, 'main/edit_domain_dns_record.html', {
        'domain': domain_obj,
        'domain_name': domain,
        'record': record,
        'record_index': record_index,
        'record_types': ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'CAA'],
    })


@login_required
def delete_domain_dns_record(request, domain, record_index):
    """Delete DNS record from Domain CR spec."""
    domain_obj = get_object_or_404(Domain, domain_name=domain)

    try:
        k8s_domain = k8s_get_domain(domain)
        dns_spec = k8s_domain.spec.get('dns', {})
        records = dns_spec.get('records', [])

        if record_index < 0 or record_index >= len(records):
            messages.error(request, "Record not found.")
            return redirect('domain_dns_records', domain=domain)

        record = records[record_index]

    except K8sNotFoundError:
        messages.error(request, f"Domain CR not found for {domain}")
        return redirect('kpmain')
    except K8sClientError as e:
        messages.error(request, f"Error fetching domain: {e}")
        return redirect('kpmain')

    if request.method == 'POST':
        try:
            k8s_delete_dns_record(domain, record_index)
            messages.success(request, f"DNS record deleted. It may take a moment to be removed from Cloudflare.")
            return redirect('domain_dns_records', domain=domain)
        except K8sClientError as e:
            messages.error(request, f"Failed to delete DNS record: {e}")
            return redirect('domain_dns_records', domain=domain)

    return render(request, 'main/delete_domain_dns_record_confirm.html', {
        'domain': domain_obj,
        'domain_name': domain,
        'record': record,
        'record_index': record_index,
    })


# Legacy functions
def create_dns_record_in_cloudflare(record_obj):
    """Legacy function - creates a DNS record in Cloudflare"""
    try:
        dns_service = CloudflareDNSService(record_obj.zone.token.api_token)
        record_data = DNSRecordData(
            record_type=record_obj.record_type,
            name=record_obj.name,
            content=record_obj.content,
            ttl=record_obj.ttl,
            proxied=record_obj.proxied,
            priority=record_obj.priority
        )
        response = dns_service.create_dns_record(record_obj.zone.zone_id, record_data)
        return response
    except Exception as e:
        logger.error(f"Error in legacy create_dns_record_in_cloudflare: {e}")
        raise


def create_cf_zone(zone_name, token):
    """Legacy function - creates a zone in Cloudflare"""
    try:
        dns_service = CloudflareDNSService(token.api_token)
        return dns_service.create_zone(zone_name)
    except Exception as e:
        logger.error(f"Error in legacy create_cf_zone: {e}")
        raise


def edit_dns_record_simple(request, record_id):
    """Simple version that only updates the database (for testing)"""
    logger.info(f"Simple edit for record_id: {record_id}")

    record = get_object_or_404(DNSRecord, id=record_id)
    zone = record.zone

    if request.method == "POST":
        logger.info(f"POST data: {dict(request.POST)}")

        try:
            record.record_type = request.POST.get('record_type', record.record_type)
            record.name = request.POST.get('name', record.name)
            record.content = request.POST.get('content', record.content)
            record.ttl = int(request.POST.get('ttl', record.ttl))
            record.proxied = 'proxied' in request.POST

            priority = request.POST.get('priority')
            if priority and priority.strip():
                record.priority = int(priority)
            elif record.record_type not in ['MX', 'SRV']:
                record.priority = None

            logger.info(f"About to save: {record.record_type} {record.name} -> {record.content}")
            record.save()
            logger.info("Database save successful")

            messages.success(request, "DNS record updated in database (simple mode).")
            return redirect("list_dns_records", zone_id=zone.id)

        except Exception as e:
            logger.error(f"Simple save error: {e}", exc_info=True)
            messages.error(request, f"Save error: {e}")

    context = {
        'record': record,
        'zone': zone,
        'record_types': DNSRecord.RECORD_TYPES,
    }

    return render(request, "main/test_edit_dns_record.html", context)
