"""
Admin views for packages, user profiles, and CBVs
"""
from django.shortcuts import get_object_or_404
from django.http import StreamingHttpResponse, HttpResponseNotFound
from django.urls import reverse, reverse_lazy
from django.views.generic import ListView, CreateView, UpdateView, FormView, View
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from kubernetes import client, config
from kubernetes.stream import stream
from kubernetes.client import ApiException

import os
import time
import subprocess

from dashboard.models import Package, UserProfile, Domain, SystemSettings
from dashboard.forms import UserProfilePackageForm, UserForm, PackageForm, UserProfileForm
from dashboard.k8s import get_backup, K8sNotFoundError
from .utils import SuperuserRequiredMixin

UPLOAD_BASE_DIR = os.getenv('WATCHDOG_UPLOAD_ROOT', '/kubepanel/watchdog/uploads')


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


class DownloadSnapshotView(View):
    def get(self, request, snapshot_name):
        # Parse backup name to extract domain (format: domain-name-TIMESTAMP)
        # e.g., example-com-20240115-020000 -> example-com
        parts = snapshot_name.rsplit('-', 2)
        if len(parts) < 3:
            return HttpResponseNotFound("Invalid backup name format")

        domain_slug = parts[0]  # e.g., example-com
        namespace = f"dom-{domain_slug}"

        # Get backup from Kubernetes
        backup = get_backup(namespace, snapshot_name)
        if not backup:
            return HttpResponseNotFound(f"Backup {snapshot_name} not found")

        # Check permissions
        domain_name = backup.domain_name
        try:
            domain = Domain.objects.get(domain_name=domain_name)
            if not request.user.is_superuser and domain.owner != request.user:
                raise PermissionDenied
        except Domain.DoesNotExist:
            raise PermissionDenied

        # Check if backup has a volume snapshot
        volume_snapshot_name = backup.status.volume_snapshot_name
        if not volume_snapshot_name:
            return HttpResponseNotFound("Backup does not have a volume snapshot")

        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()

        pod_name = None
        lv_name = None
        piraeus_namespace = "piraeus-datastore"
        container = "linstor-satellite"
        snap_namespace = domain_slug

        co_api = client.CustomObjectsApi()
        obj = co_api.get_namespaced_custom_object(
            group="snapshot.storage.k8s.io",
            version="v1",
            namespace=namespace,  # Domain namespace (dom-example-com)
            plural="volumesnapshots",
            name=volume_snapshot_name,
        )
        content_name = obj["status"]["boundVolumeSnapshotContentName"]
        snap_id = content_name.split('-', 1)[1]
        v1 = client.CoreV1Api()
        pods = v1.list_namespaced_pod(
            piraeus_namespace,
            label_selector="app.kubernetes.io/component=linstor-satellite"
        ).items

        for pod in pods:
            name = pod.metadata.name
            cmd_check = [
                "sh", "-c",
                f"lvs --noheadings -o lv_name linstorvg | grep {snap_id}"
            ]
            try:
                out = stream(
                    v1.connect_get_namespaced_pod_exec,
                    name=name,
                    namespace=piraeus_namespace,
                    container=container,
                    command=cmd_check,
                    stderr=False, stdin=False, stdout=True, tty=False,
                ).strip()
            except ApiException:
                continue
            if out:
                pod_name = name
                lv_name = out
                break

        if not pod_name or not lv_name:
            return HttpResponseNotFound(f"Volume snapshot {volume_snapshot_name} not found in storage")

        cmd = [
            "kubectl", "exec", "-i",
            "-n", piraeus_namespace,
            pod_name, "-c", container,
            "--", "sh", "-c",
            f"thin_send linstorvg/{lv_name} | zstd -3 -c"
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        def stream_generator():
            for chunk in iter(lambda: proc.stdout.read(64*1024), b""):
                yield chunk
            code = proc.wait()
            if code != 0:
                err = proc.stderr.read().decode(errors="ignore")
                raise Exception(f"kubectl exec failed: {err}")

        response = StreamingHttpResponse(stream_generator(), content_type="application/octet-stream")
        response["Content-Disposition"] = f'attachment; filename="{snapshot_name}.lv.zst"'
        return response


class DownloadSqlDumpView(View):
    def get(self, request, dump_name):
        # Parse backup name to extract domain (format: domain-name-TIMESTAMP)
        parts = dump_name.rsplit('-', 2)
        if len(parts) < 3:
            return HttpResponseNotFound("Invalid backup name format")

        domain_slug = parts[0]
        namespace = f"dom-{domain_slug}"

        # Get backup from Kubernetes
        backup = get_backup(namespace, dump_name)
        if not backup:
            return HttpResponseNotFound(f"Backup {dump_name} not found")

        # Check permissions
        domain_name = backup.domain_name
        try:
            domain = Domain.objects.get(domain_name=domain_name)
            if not request.user.is_superuser and domain.owner != request.user:
                raise PermissionDenied
        except Domain.DoesNotExist:
            raise PermissionDenied

        # Check if backup has a database backup path
        db_backup_path = backup.status.database_backup_path
        if not db_backup_path:
            return HttpResponseNotFound("Backup does not have a database backup")

        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()

        # The backup PVC is in the domain namespace with name "backup"
        pvc_name = "backup"
        file_path = db_backup_path  # e.g., /backup/20240115-020000/database.mariabackup.zst

        # The file_path is relative to /backup mount point, e.g., /backup/20240115/database.mariabackup.zst
        # We need to mount the backup PVC and cat the file
        job_body = {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {"generateName": f"backup-downloader-{domain_slug}-"},
            "spec": {
                "ttlSecondsAfterFinished": 60,
                "template": {
                    "spec": {
                        "restartPolicy": "Never",
                        "volumes": [{
                            "name": "backup-pvc",
                            "persistentVolumeClaim": {"claimName": pvc_name}
                        }],
                        "containers": [{
                            "name": "downloader",
                            "image": "alpine:latest",
                            "command": ["sh", "-c", "sleep 3600"],
                            "volumeMounts": [{"mountPath": "/backup", "name": "backup-pvc"}]
                        }]
                    }
                }
            }
        }

        batch_v1 = client.BatchV1Api()
        core_v1 = client.CoreV1Api()

        job = batch_v1.create_namespaced_job(namespace=namespace, body=job_body)
        job_name = job.metadata.name

        pod_name = None
        for _ in range(60):
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
            return HttpResponseNotFound("Failed to start job pod")

        cmd = ["cat", file_path]
        exec_stream = stream(
            core_v1.connect_get_namespaced_pod_exec,
            name=pod_name,
            namespace=namespace,
            container="downloader",
            command=cmd,
            stderr=True, stdin=False, stdout=True, tty=False,
            _preload_content=False
        )

        def generator():
            try:
                while exec_stream.is_open():
                    exec_stream.update(timeout=1)
                    chunk = exec_stream.read_stdout()
                    if chunk:
                        yield chunk
            finally:
                exec_stream.close()
                batch_v1.delete_namespaced_job(
                    name=job_name,
                    namespace=namespace,
                    body=client.V1DeleteOptions(propagation_policy='Foreground')
                )

        # Extract filename from the backup path for download
        download_filename = f"{dump_name}.mariabackup.zst"
        response = StreamingHttpResponse(generator(), content_type="application/octet-stream")
        response["Content-Disposition"] = f'attachment; filename="{download_filename}"'
        return response


class UploadRestoreFilesView(View):
    """Upload .lv.zst file and queue for restore"""

    def get(self, request, domain_name):
        domain = get_object_or_404(Domain, domain_name=domain_name)
        if not request.user.is_superuser and domain.owner != request.user:
            raise PermissionDenied
        return render(request, 'main/upload_snapshot.html', {
            'domain_name': domain_name
        })

    def post(self, request, domain_name):
        from django.shortcuts import render, redirect
        domain = get_object_or_404(Domain, domain_name=domain_name)
        if not request.user.is_superuser and domain.owner != request.user:
            raise PermissionDenied

        domain_name_dash = domain_name.replace(".", "-")
        pvc_name = f"{domain_name_dash}-pvc"

        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        v1 = client.CoreV1Api()
        try:
            pvc = v1.read_namespaced_persistent_volume_claim(
                name=pvc_name,
                namespace=domain_name_dash
            )
        except client.exceptions.ApiException:
            messages.error(request, f"PVC {pvc_name} not found in namespace {domain_name}.")
            return redirect(reverse('upload_restore', args=[domain_name]))

        pv_name = pvc.spec.volume_name

        domain_dir = os.path.join(UPLOAD_BASE_DIR, domain_name)
        os.makedirs(domain_dir, exist_ok=True)

        snapshot_file = request.FILES.get('snapshot_file')
        if not snapshot_file:
            messages.error(request, 'No snapshot file provided.')
            return redirect(reverse('upload_restore', args=[domain_name]))

        filename = snapshot_file.name
        if not filename.endswith('.lv.zst'):
            messages.error(request, 'Invalid file type; must be .lv.zst')
            return redirect(reverse('upload_restore', args=[domain_name]))

        job_id = filename.rsplit('.', 2)[0]
        job_dir = os.path.join(domain_dir, job_id)
        os.makedirs(job_dir, exist_ok=True)

        dest_path = os.path.join(job_dir, filename)
        with open(dest_path, 'wb') as dest:
            for chunk in snapshot_file.chunks():
                dest.write(chunk)

        ready_path = os.path.join(job_dir, 'READY')
        with open(ready_path, 'w') as sem:
            sem.write(pv_name)

        messages.success(request, 'Snapshot uploaded and queued for restore.')
        return redirect(reverse('upload_restore', args=[domain_name]))


# Need to import render for UploadRestoreFilesView
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect


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
