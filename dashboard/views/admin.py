"""
Admin views for packages, user profiles, and CBVs
"""
from django.shortcuts import get_object_or_404, render, redirect
from django.http import HttpResponseNotFound
from django.urls import reverse, reverse_lazy
from django.views.generic import ListView, CreateView, UpdateView, FormView, View
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from kubernetes import client, config
from kubernetes.client import ApiException

import json
import logging
import os
import tarfile
import tempfile
import time
import uuid

from dashboard.models import Package, UserProfile, Domain, SystemSettings
from dashboard.forms import UserProfilePackageForm, UserForm, PackageForm, UserProfileForm
from dashboard.k8s import create_restore
from .utils import SuperuserRequiredMixin

logger = logging.getLogger(__name__)

# Maximum upload size: 10GB
MAX_UPLOAD_SIZE = 10 * 1024 * 1024 * 1024


class PackageListView(SuperuserRequiredMixin, ListView):
    model = Package
    template_name = 'main/package_list.html'
    context_object_name = 'packages'


class PackageCreateView(SuperuserRequiredMixin, CreateView):
    model = Package
    form_class = PackageForm
    template_name = 'main/package_form.html'
    success_url = reverse_lazy('list_packages')


class PackageUpdateView(SuperuserRequiredMixin, UpdateView):
    model = Package
    form_class = PackageForm
    template_name = 'main/package_form.html'
    success_url = reverse_lazy('list_packages')


class UserProfileListView(SuperuserRequiredMixin, ListView):
    model = UserProfile
    template_name = 'main/userprofile_list.html'
    context_object_name = 'profiles'


class UserProfileCreateView(SuperuserRequiredMixin, CreateView):
    model = UserProfile
    form_class = UserProfileForm
    template_name = 'main/userprofile_form.html'
    success_url = reverse_lazy('list_userprofiles')


class UserProfileUpdateView(SuperuserRequiredMixin, UpdateView):
    model = UserProfile
    form_class = UserProfileForm
    template_name = 'main/userprofile_form.html'
    success_url = reverse_lazy('list_userprofiles')


class UserCreateView(SuperuserRequiredMixin, FormView):
    template_name = 'main/user_create.html'
    form_class = UserForm
    success_url = reverse_lazy('list_userprofiles')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['packages'] = Package.objects.all()
        return context

    def form_valid(self, form):
        user = form.save()
        pkg_id = self.request.POST.get('package')
        profile = UserProfile.objects.get(user=user)
        if pkg_id:
            profile.package_id = pkg_id
            profile.save()
        messages.success(self.request, 'User created successfully.')
        return super().form_valid(form)


class UserProfilePackageUpdateView(SuperuserRequiredMixin, UpdateView):
    model = UserProfile
    form_class = UserProfilePackageForm
    template_name = 'main/userprofile_edit.html'
    pk_url_kwarg = 'pk'
    success_url = reverse_lazy('list_userprofiles')

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['user'] = self.object.user
        return ctx


def _load_k8s_config():
    """Load Kubernetes configuration."""
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()


def _upload_archive_to_pvc(namespace: str, archive_path: str, dest_path: str) -> None:
    """
    Upload a tar.gz archive to the backup PVC in a domain namespace.

    Creates a temporary job to copy the file to the PVC.
    """
    _load_k8s_config()
    batch_v1 = client.BatchV1Api()
    core_v1 = client.CoreV1Api()

    unique_id = str(uuid.uuid4())[:8]
    job_name = f"upload-restore-{unique_id}"

    job_body = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": job_name,
            "namespace": namespace,
        },
        "spec": {
            "ttlSecondsAfterFinished": 60,
            "template": {
                "spec": {
                    "restartPolicy": "Never",
                    "volumes": [
                        {
                            "name": "backup-pvc",
                            "persistentVolumeClaim": {"claimName": "backup"}
                        }
                    ],
                    "containers": [{
                        "name": "uploader",
                        "image": "alpine:latest",
                        "command": ["sh", "-c", "sleep 3600"],
                        "volumeMounts": [
                            {"mountPath": "/backup", "name": "backup-pvc"}
                        ]
                    }]
                }
            }
        }
    }

    batch_v1.create_namespaced_job(namespace=namespace, body=job_body)

    # Wait for pod to be running
    pod_name = None
    for _ in range(120):
        pods = core_v1.list_namespaced_pod(
            namespace=namespace,
            label_selector=f"job-name={job_name}"
        ).items
        if pods:
            pod = pods[0]
            pod_name = pod.metadata.name
            if pod.status.phase == "Running":
                break
        time.sleep(1)

    if not pod_name:
        batch_v1.delete_namespaced_job(
            name=job_name,
            namespace=namespace,
            body=client.V1DeleteOptions(propagation_policy='Foreground')
        )
        raise TimeoutError("Upload job pod did not start within timeout")

    try:
        # Create the destination directory
        import subprocess
        mkdir_cmd = [
            "kubectl", "exec", "-n", namespace, pod_name, "-c", "uploader",
            "--", "mkdir", "-p", os.path.dirname(dest_path)
        ]
        subprocess.run(mkdir_cmd, check=True, capture_output=True)

        # Copy the file to the pod
        cp_cmd = [
            "kubectl", "cp", archive_path,
            f"{namespace}/{pod_name}:{dest_path}",
            "-c", "uploader"
        ]
        subprocess.run(cp_cmd, check=True, capture_output=True)

    finally:
        batch_v1.delete_namespaced_job(
            name=job_name,
            namespace=namespace,
            body=client.V1DeleteOptions(propagation_policy='Foreground')
        )


class UploadRestoreFilesView(View):
    """
    Upload a tar.gz backup archive and trigger restore.

    Accepts portable tar.gz archives containing:
    - www/ - Site files
    - database.sql - MariaDB dump
    - manifest.json - Backup metadata (optional)
    """

    def get(self, request, domain_name):
        domain = get_object_or_404(Domain, domain_name=domain_name)
        if not request.user.is_superuser and domain.owner != request.user:
            raise PermissionDenied
        return render(request, 'main/upload_restore.html', {
            'domain': domain,
            'max_upload_size_gb': MAX_UPLOAD_SIZE // (1024 * 1024 * 1024),
        })

    def post(self, request, domain_name):
        domain = get_object_or_404(Domain, domain_name=domain_name)
        if not request.user.is_superuser and domain.owner != request.user:
            raise PermissionDenied

        archive_file = request.FILES.get('archive_file')
        if not archive_file:
            messages.error(request, 'No archive file provided.')
            return redirect(reverse('upload_restore', args=[domain_name]))

        # Validate file type
        filename = archive_file.name
        if not filename.endswith('.tar.gz') and not filename.endswith('.tgz'):
            messages.error(request, 'Invalid file type. Please upload a .tar.gz file.')
            return redirect(reverse('upload_restore', args=[domain_name]))

        # Check file size
        if archive_file.size > MAX_UPLOAD_SIZE:
            messages.error(
                request,
                f'File too large. Maximum size is {MAX_UPLOAD_SIZE // (1024*1024*1024)}GB.'
            )
            return redirect(reverse('upload_restore', args=[domain_name]))

        namespace = f"dom-{domain_name.replace('.', '-')}"

        # Save to temporary file and validate
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.tar.gz') as tmp:
                for chunk in archive_file.chunks():
                    tmp.write(chunk)
                tmp_path = tmp.name

            # Validate the archive
            try:
                with tarfile.open(tmp_path, 'r:gz') as tar:
                    members = tar.getnames()

                    # Check for required content (at least one of www/ or database.sql)
                    has_www = any(m.startswith('www/') or m == 'www' for m in members)
                    has_db = 'database.sql' in members

                    if not has_www and not has_db:
                        messages.error(
                            request,
                            'Invalid archive: must contain www/ directory or database.sql file.'
                        )
                        os.unlink(tmp_path)
                        return redirect(reverse('upload_restore', args=[domain_name]))

            except tarfile.TarError as e:
                messages.error(request, f'Invalid tar.gz archive: {e}')
                os.unlink(tmp_path)
                return redirect(reverse('upload_restore', args=[domain_name]))

            # Generate unique restore name
            from datetime import datetime
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            restore_name = f"uploaded-{timestamp}"
            dest_path = f"/backup/uploaded/{restore_name}/archive.tar.gz"

            # Upload to backup PVC
            try:
                _upload_archive_to_pvc(namespace, tmp_path, dest_path)
            except TimeoutError as e:
                messages.error(request, f'Failed to upload archive: {e}')
                os.unlink(tmp_path)
                return redirect(reverse('upload_restore', args=[domain_name]))
            except Exception as e:
                logger.exception(f"Failed to upload archive for {domain_name}")
                messages.error(request, f'Failed to upload archive: {e}')
                os.unlink(tmp_path)
                return redirect(reverse('upload_restore', args=[domain_name]))

            # Clean up temp file
            os.unlink(tmp_path)

            # Create Restore CR
            try:
                create_restore(
                    namespace=namespace,
                    domain_name=domain_name,
                    backup_name=f"uploaded-{restore_name}",
                    volume_snapshot_name=None,  # No snapshot for uploaded restores
                    database_backup_path=dest_path,
                    restore_type="uploaded",
                    uploaded_archive_path=dest_path,
                )
                messages.success(
                    request,
                    'Archive uploaded successfully. Restore has been initiated.'
                )
            except Exception as e:
                logger.exception(f"Failed to create Restore CR for {domain_name}")
                messages.error(request, f'Failed to initiate restore: {e}')

            return redirect(reverse('volumesnapshots', args=[domain_name]))

        except Exception as e:
            logger.exception(f"Upload restore failed for {domain_name}")
            messages.error(request, f'Upload failed: {e}')
            if 'tmp_path' in locals() and os.path.exists(tmp_path):
                os.unlink(tmp_path)
            return redirect(reverse('upload_restore', args=[domain_name]))


@login_required
def reset_user_password(request, pk):
    """Reset a user's password (superuser only)."""
    if not request.user.is_superuser:
        messages.error(request, "You don't have permission to reset passwords.")
        return redirect('list_userprofiles')

    user = get_object_or_404(User, pk=pk)

    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if not new_password:
            messages.error(request, 'Password is required.')
        elif new_password != confirm_password:
            messages.error(request, 'Passwords do not match.')
        elif len(new_password) < 8:
            messages.error(request, 'Password must be at least 8 characters long.')
        else:
            user.set_password(new_password)
            user.save()
            messages.success(request, f'Password for {user.username} has been reset.')
            return redirect('list_userprofiles')

    return render(request, 'main/reset_user_password.html', {'target_user': user})


@login_required
def delete_user(request, pk):
    """Delete a user (superuser only). Cannot delete superusers."""
    if not request.user.is_superuser:
        messages.error(request, "You don't have permission to delete users.")
        return redirect('list_userprofiles')

    user = get_object_or_404(User, pk=pk)

    if user.is_superuser:
        messages.error(request, 'Cannot delete a superuser account.')
        return redirect('list_userprofiles')

    if request.method == 'POST':
        username = user.username
        # Check if user has domains
        user_domains = Domain.objects.filter(owner=user)
        if user_domains.exists():
            messages.error(
                request,
                f'Cannot delete user {username}. They own {user_domains.count()} domain(s). '
                'Please delete or transfer the domains first.'
            )
            return redirect('list_userprofiles')

        user.delete()
        messages.success(request, f'User {username} has been deleted.')
        return redirect('list_userprofiles')

    return render(request, 'main/delete_user.html', {'target_user': user})


@login_required
def system_settings(request):
    """View and edit system-wide settings (superuser only)."""
    if not request.user.is_superuser:
        return redirect('kpmain')

    settings_obj = SystemSettings.get_settings()

    if request.method == 'POST':
        try:
            settings_obj.mail_queue_warning_threshold = int(
                request.POST.get('mail_queue_warning', 50)
            )
            settings_obj.mail_queue_error_threshold = int(
                request.POST.get('mail_queue_error', 100)
            )
            settings_obj.health_check_email_enabled = 'email_enabled' in request.POST
            settings_obj.save()
            messages.success(request, 'Settings saved successfully.')
        except (ValueError, TypeError) as e:
            messages.error(request, f'Invalid value: {e}')
        return redirect('system_settings')

    return render(request, 'main/system_settings.html', {
        'settings': settings_obj,
    })
