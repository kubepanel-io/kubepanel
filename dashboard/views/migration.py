"""
cPanel Migration Views

Handles the UI for bulk migration from cPanel servers to KubePanel.
"""

import json
import logging
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.text import slugify
from django.views.decorators.http import require_POST
from django.views.generic import ListView, DetailView, View

from dashboard.models import (
    MigrationBatch,
    MigrationDomain,
    Package,
    SystemSettings,
)
from dashboard.services.cpanel_api import (
    CPanelClient,
    CPanelAPIError,
    CPanelConnectionError,
    serialize_domain_info,
)
from dashboard.services.migration_job import (
    create_migration_job,
    get_migration_job_status,
    delete_migration_job,
)
from .utils import SuperuserRequiredMixin

logger = logging.getLogger(__name__)


def migration_feature_required(view_func):
    """
    Decorator to check if cPanel migration feature is enabled.
    """
    def wrapper(request, *args, **kwargs):
        try:
            settings = SystemSettings.get_settings()
            if not settings.cpanel_migration_enabled:
                messages.error(
                    request,
                    'cPanel Migration feature is not enabled. '
                    'Enable it in System Settings.'
                )
                return redirect('kpmain')
        except SystemSettings.DoesNotExist:
            messages.error(request, 'System settings not configured.')
            return redirect('kpmain')

        if not request.user.is_superuser:
            messages.error(
                request,
                'Only superusers can access cPanel Migration.'
            )
            return redirect('kpmain')

        return view_func(request, *args, **kwargs)
    return wrapper


class MigrationListView(SuperuserRequiredMixin, ListView):
    """
    Screen 1: Migration Dashboard

    Shows list of all migration batches with status.
    """
    model = MigrationBatch
    template_name = 'main/migration_list.html'
    context_object_name = 'batches'
    ordering = ['-created_at']

    def dispatch(self, request, *args, **kwargs):
        # Check feature flag
        try:
            settings = SystemSettings.get_settings()
            if not settings.cpanel_migration_enabled:
                messages.error(
                    request,
                    'cPanel Migration feature is not enabled.'
                )
                return redirect('kpmain')
        except SystemSettings.DoesNotExist:
            messages.error(request, 'System settings not configured.')
            return redirect('kpmain')

        return super().dispatch(request, *args, **kwargs)


class MigrationConnectView(SuperuserRequiredMixin, View):
    """
    Screen 2: Connect to cPanel Server

    User provides cPanel server credentials.
    On success, creates a MigrationBatch and discovers domains.
    """
    template_name = 'main/migration_connect.html'

    def dispatch(self, request, *args, **kwargs):
        # Check feature flag
        try:
            settings = SystemSettings.get_settings()
            if not settings.cpanel_migration_enabled:
                messages.error(
                    request,
                    'cPanel Migration feature is not enabled.'
                )
                return redirect('kpmain')
        except SystemSettings.DoesNotExist:
            messages.error(request, 'System settings not configured.')
            return redirect('kpmain')

        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        hostname = request.POST.get('hostname', '').strip()
        port = request.POST.get('port', '2087').strip()
        username = request.POST.get('username', '').strip()
        api_token = request.POST.get('api_token', '').strip()
        verify_ssl = request.POST.get('verify_ssl') == 'on'

        # Validate inputs
        errors = []
        if not hostname:
            errors.append('Hostname is required.')
        if not username:
            errors.append('Username is required.')
        if not api_token:
            errors.append('API Token is required.')

        try:
            port = int(port)
            if port < 1 or port > 65535:
                errors.append('Port must be between 1 and 65535.')
        except ValueError:
            errors.append('Port must be a valid number.')
            port = 2083

        if errors:
            for error in errors:
                messages.error(request, error)
            return render(request, self.template_name, {
                'hostname': hostname,
                'port': port,
                'username': username,
            })

        # Try to connect and discover domains
        try:
            client = CPanelClient(
                hostname=hostname,
                port=port,
                username=username,
                api_token=api_token,
                verify_ssl=verify_ssl,
            )

            # Test connection
            client.test_connection()

            # Discover domains
            domains = client.list_domains()

            # Create batch with encrypted API token
            batch = MigrationBatch.objects.create(
                cpanel_hostname=hostname,
                cpanel_port=port,
                cpanel_username=username,
                cpanel_verify_ssl=verify_ssl,
                created_by=request.user,
                status='configuring',
                discovered_domains=[serialize_domain_info(d) for d in domains],
            )
            # Encrypt and store the API token
            batch.set_api_token(api_token)
            batch.save()

            messages.success(
                request,
                f'Connected successfully. Found {len(domains)} domain(s).'
            )
            return redirect('migration_select', batch_id=batch.id)

        except CPanelConnectionError as e:
            messages.error(request, f'Connection failed: {e}')
        except CPanelAPIError as e:
            messages.error(request, f'API error: {e}')
        except Exception as e:
            logger.exception('Unexpected error connecting to cPanel')
            messages.error(request, f'Unexpected error: {e}')

        return render(request, self.template_name, {
            'hostname': hostname,
            'port': port,
            'username': username,
        })


class MigrationSelectView(SuperuserRequiredMixin, View):
    """
    Screen 3: Select Domains to Migrate

    Shows discovered domains with expandable configuration boxes.
    """
    template_name = 'main/migration_select.html'

    def dispatch(self, request, *args, **kwargs):
        # Check feature flag
        try:
            settings = SystemSettings.get_settings()
            if not settings.cpanel_migration_enabled:
                messages.error(
                    request,
                    'cPanel Migration feature is not enabled.'
                )
                return redirect('kpmain')
        except SystemSettings.DoesNotExist:
            messages.error(request, 'System settings not configured.')
            return redirect('kpmain')

        return super().dispatch(request, *args, **kwargs)

    def get(self, request, batch_id):
        batch = get_object_or_404(MigrationBatch, id=batch_id)

        # Only allow configuring batches
        if batch.status != 'configuring':
            messages.error(request, 'This migration batch is no longer configurable.')
            return redirect('migration_detail', batch_id=batch.id)

        return render(request, self.template_name, {
            'batch': batch,
            'domains': batch.discovered_domains,
            'users': User.objects.filter(is_active=True).order_by('username'),
            'packages': Package.objects.all().order_by('name'),
        })

    def post(self, request, batch_id):
        batch = get_object_or_404(MigrationBatch, id=batch_id)

        if batch.status != 'configuring':
            messages.error(request, 'This migration batch is no longer configurable.')
            return redirect('migration_detail', batch_id=batch.id)

        # Parse form data for each domain
        selected_count = 0
        for domain_data in batch.discovered_domains:
            domain_name = domain_data['name']
            safe_name = slugify(domain_name)  # Must match template's |slugify filter

            # Check if this domain was selected
            if request.POST.get(f'select_{safe_name}'):
                # Get configuration for this domain
                target_owner_id = request.POST.get(f'owner_{safe_name}')
                target_package_id = request.POST.get(f'package_{safe_name}')
                selected_database = request.POST.get(f'database_{safe_name}', '')
                selected_mailboxes = request.POST.getlist(f'mailboxes_{safe_name}')
                email_method = request.POST.get(f'email_method_{safe_name}', 'backup')

                if not target_owner_id:
                    messages.error(
                        request,
                        f'Please select an owner for {domain_name}.'
                    )
                    return self.get(request, batch_id)

                # Create MigrationDomain record
                MigrationDomain.objects.create(
                    batch=batch,
                    source_domain=domain_name,
                    source_username=domain_data.get('user', batch.cpanel_username),
                    target_owner_id=target_owner_id,
                    target_package_id=target_package_id if target_package_id else None,
                    available_databases=domain_data.get('databases', []),
                    selected_database=selected_database,
                    available_mailboxes=domain_data.get('mailboxes', []),
                    selected_mailboxes=selected_mailboxes,
                    email_method=email_method,
                )
                selected_count += 1

        if selected_count == 0:
            messages.error(request, 'Please select at least one domain to migrate.')
            return self.get(request, batch_id)

        # Update batch status
        batch.status = 'pending'
        batch.save()

        # Start migration job
        try:
            job_name = self._create_migration_job(batch)
            batch.job_name = job_name
            batch.status = 'running'
            batch.started_at = timezone.now()
            batch.save()

            messages.success(
                request,
                f'Migration started for {selected_count} domain(s).'
            )
        except Exception as e:
            logger.exception('Failed to create migration job')
            messages.error(request, f'Failed to start migration: {e}')
            batch.status = 'failed'
            batch.save()

        return redirect('migration_detail', batch_id=batch.id)

    def _create_migration_job(self, batch: MigrationBatch) -> str:
        """
        Create a Kubernetes Job to process the migration batch.

        Returns:
            Job name
        """
        return create_migration_job(batch.id)


class MigrationDetailView(SuperuserRequiredMixin, DetailView):
    """
    Screen 4: Migration Progress

    Shows progress of migration batch with per-domain status.
    """
    model = MigrationBatch
    template_name = 'main/migration_detail.html'
    pk_url_kwarg = 'batch_id'
    context_object_name = 'batch'

    def dispatch(self, request, *args, **kwargs):
        # Check feature flag
        try:
            settings = SystemSettings.get_settings()
            if not settings.cpanel_migration_enabled:
                messages.error(
                    request,
                    'cPanel Migration feature is not enabled.'
                )
                return redirect('kpmain')
        except SystemSettings.DoesNotExist:
            messages.error(request, 'System settings not configured.')
            return redirect('kpmain')

        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['migration_domains'] = self.object.domains.all().order_by('id')
        return context


@login_required
@migration_feature_required
def migration_test_connection(request):
    """
    AJAX endpoint to test cPanel connection without creating a batch.
    """
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'POST required'}, status=405)

    hostname = request.POST.get('hostname', '').strip()
    port = request.POST.get('port', '2087').strip()
    username = request.POST.get('username', '').strip()
    api_token = request.POST.get('api_token', '').strip()
    verify_ssl = request.POST.get('verify_ssl') == 'true'

    if not all([hostname, username, api_token]):
        return JsonResponse({
            'success': False,
            'message': 'All fields are required.'
        })

    try:
        port = int(port)
    except ValueError:
        return JsonResponse({
            'success': False,
            'message': 'Invalid port number.'
        })

    try:
        client = CPanelClient(
            hostname=hostname,
            port=port,
            username=username,
            api_token=api_token,
            verify_ssl=verify_ssl,
        )
        client.test_connection()

        return JsonResponse({
            'success': True,
            'message': 'Connection successful!'
        })

    except CPanelConnectionError as e:
        return JsonResponse({
            'success': False,
            'message': f'Connection failed: {e}'
        })
    except CPanelAPIError as e:
        return JsonResponse({
            'success': False,
            'message': f'API error: {e}'
        })
    except Exception as e:
        logger.exception('Unexpected error testing cPanel connection')
        return JsonResponse({
            'success': False,
            'message': f'Unexpected error: {e}'
        })


@login_required
@migration_feature_required
def migration_status_api(request, batch_id):
    """
    AJAX endpoint for live status updates.

    Returns JSON with batch status and per-domain progress.
    """
    batch = get_object_or_404(MigrationBatch, id=batch_id)

    return JsonResponse({
        'status': batch.status,
        'total_domains': batch.total_domains,
        'completed_domains': batch.completed_domains,
        'failed_domains': batch.failed_domains,
        'backup_status': batch.backup_status,
        'backup_progress': batch.backup_progress,
        'domains': [
            {
                'id': d.id,
                'name': d.source_domain,
                'status': d.status,
                'status_display': d.get_status_display(),
                'progress': d.progress_percent,
                'message': d.progress_message,
                'error': d.error_message,
            }
            for d in batch.domains.all().order_by('id')
        ]
    })


@login_required
@migration_feature_required
@require_POST
def migration_cancel(request, batch_id):
    """
    Cancel a running migration batch.
    """
    batch = get_object_or_404(MigrationBatch, id=batch_id)

    if batch.status not in ['pending', 'running']:
        messages.error(request, 'Cannot cancel a migration that is not running.')
        return redirect('migration_detail', batch_id=batch_id)

    # Delete K8s Job if it exists
    if batch.job_name:
        try:
            delete_migration_job(batch.job_name)
            logger.info(f"Deleted migration job: {batch.job_name}")
        except Exception as e:
            logger.exception(f'Failed to delete migration job {batch.job_name}')

    batch.status = 'cancelled'
    batch.completed_at = timezone.now()
    batch.save()

    # Mark all queued domains as skipped
    batch.domains.filter(status='queued').update(status='skipped')

    messages.success(request, 'Migration cancelled.')
    return redirect('migration_detail', batch_id=batch_id)


@login_required
@migration_feature_required
@require_POST
def migration_retry_failed(request, batch_id):
    """
    Retry all failed domains in a batch.
    """
    batch = get_object_or_404(MigrationBatch, id=batch_id)

    if batch.status not in ['completed', 'failed']:
        messages.error(request, 'Cannot retry a migration that is still running.')
        return redirect('migration_detail', batch_id=batch_id)

    failed_count = batch.domains.filter(status='failed').count()
    if failed_count == 0:
        messages.info(request, 'No failed domains to retry.')
        return redirect('migration_detail', batch_id=batch_id)

    # Reset failed domains to queued
    batch.domains.filter(status='failed').update(
        status='queued',
        error_message='',
        progress_percent=0,
        progress_message='',
    )

    # Create new job
    try:
        job_name = create_migration_job(batch.id)
        batch.job_name = job_name
        batch.status = 'running'
        batch.save()

        logger.info(f"Created retry migration job: {job_name}")
        messages.success(request, f'Retrying {failed_count} failed domain(s).')
    except Exception as e:
        logger.exception('Failed to create retry migration job')
        messages.error(request, f'Failed to start retry: {e}')

    return redirect('migration_detail', batch_id=batch_id)


@login_required
@migration_feature_required
@require_POST
def migration_delete(request, batch_id):
    """
    Delete a migration batch (only if not running).
    """
    batch = get_object_or_404(MigrationBatch, id=batch_id)

    if batch.status in ['pending', 'running']:
        messages.error(request, 'Cannot delete a migration that is running. Cancel it first.')
        return redirect('migration_detail', batch_id=batch_id)

    batch.delete()
    messages.success(request, 'Migration batch deleted.')
    return redirect('migration_list')
