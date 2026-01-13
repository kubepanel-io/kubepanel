"""
Mail user and alias management views
"""
import os
import subprocess
import tarfile
import tempfile

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import StreamingHttpResponse

from kubernetes import client, config

from dashboard.models import Domain, MailUser, MailAlias, LogEntry
from dashboard.forms import MailUserForm, MailAliasForm

# Maximum upload size: 5GB for mailboxes
MAX_MAILBOX_UPLOAD_SIZE = 5 * 1024 * 1024 * 1024


@login_required
def list_mail_users(request):
    if request.user.is_superuser:
        mail_users = MailUser.objects.all()
    else:
        mail_users = MailUser.objects.filter(domain__owner=request.user)
    return render(request, "main/list_mail_users.html", {"mail_users": mail_users})


@login_required
def create_mail_user(request):
    if request.method == 'POST':
        form = MailUserForm(request.POST, user=request.user)
        if form.is_valid():
            if not request.user.is_superuser:
                domain_obj = form.cleaned_data['domain']
                if domain_obj.owner != request.user:
                    return render(request, "main/error.html", {"error": "You do not own this domain."})

            form.save()
            return redirect("list_mail_users")
    else:
        form = MailUserForm(user=request.user)
    return render(request, "main/create_mail_user.html", {"form": form})


@login_required
def edit_mail_user(request, user_id):
    mail_user = get_object_or_404(MailUser, pk=user_id)
    aliases = MailAlias.objects.filter(destination__iexact=mail_user.email)
    if not request.user.is_superuser and mail_user.domain.owner != request.user:
        return render(request, "main/error.html", {"error": "Permission denied."})

    if request.method == 'POST':
        form = MailUserForm(request.POST, instance=mail_user)
        if form.is_valid():
            if not request.user.is_superuser:
                domain_obj = form.cleaned_data['domain']
                if domain_obj.owner != request.user:
                    return render(request, "main/error.html", {"error": "You do not own this domain."})
            form.save()
            return redirect("list_mail_users")
    else:
        form = MailUserForm(user=request.user, instance=mail_user)
    return render(request, "main/edit_mail_user.html", {"form": form, 'mail_user': mail_user, 'aliases': aliases})


@login_required
def delete_mail_user(request, user_id):
    mail_user = get_object_or_404(MailUser, pk=user_id)
    if not request.user.is_superuser and mail_user.domain.owner != request.user:
        return render(request, "mail/error.html", {"error": "Permission denied."})

    if request.method == 'POST':
        mail_user.delete()
        return redirect("list_mail_users")
    return render(request, "main/delete_mail_user.html", {"mail_user": mail_user})


@login_required
def mail_alias_list(request):
    qs = MailAlias.objects.select_related('domain')
    if not request.user.is_superuser:
        qs = qs.filter(domain__owner=request.user)
    return render(request, 'main/mail_alias_list.html', {
        'aliases': qs.order_by('source'),
    })


@login_required
def mail_alias_create(request):
    initial = {}
    dest = request.GET.get('destination')
    if dest:
        initial['destination'] = dest

    if request.method == 'POST':
        form = MailAliasForm(request.POST, user=request.user)
        if form.is_valid():
            form.save()
            return redirect('list_mail_users')
    else:
        form = MailAliasForm(initial=initial, user=request.user)

    return render(request, 'main/mail_alias_form.html', {'form': form})


@login_required
def mail_alias_edit(request, pk):
    alias = get_object_or_404(MailAlias, pk=pk)
    if not request.user.is_superuser and alias.domain.owner != request.user:
        return redirect('mail_alias_list')

    if request.method == 'POST':
        form = MailAliasForm(request.POST, instance=alias, user=request.user)
        if form.is_valid():
            form.save()
            return redirect('mail_alias_list')
    else:
        form = MailAliasForm(instance=alias, user=request.user)

    return render(request, 'main/mail_alias_form.html', {
        'form': form,
        'alias': alias,
    })


@login_required
def mail_alias_delete(request, pk):
    alias = get_object_or_404(MailAlias, pk=pk)
    if not request.user.is_superuser and alias.domain.owner != request.user:
        return redirect('list_mail_users')

    if request.method == 'POST':
        alias.delete()
        return redirect('list_mail_users')

    return render(request, 'main/mail_alias_confirm_delete.html', {
        'alias': alias,
    })


@login_required
def download_mailbox(request, user_id):
    """
    Download entire mailbox as .tar.gz archive.

    Streams tarball directly from SMTP pod to user via kubectl exec.
    """
    # Get mail user (with ownership check)
    try:
        if request.user.is_superuser:
            mail_user = MailUser.objects.get(pk=user_id)
        else:
            mail_user = MailUser.objects.get(pk=user_id, domain__owner=request.user)
    except MailUser.DoesNotExist:
        messages.error(request, "Email account not found.")
        return redirect('list_mail_users')

    domain_name = mail_user.domain.domain_name
    local_part = mail_user.local_part
    maildir_path = f"/var/mail/vmail/{domain_name}/{local_part}"

    # Load Kubernetes config
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()

    v1 = client.CoreV1Api()

    # Find SMTP pod
    try:
        pods = v1.list_namespaced_pod(
            namespace='kubepanel',
            label_selector='app=smtp'
        )
    except Exception as e:
        messages.error(request, f"Failed to connect to Kubernetes: {e}")
        return redirect('list_mail_users')

    if not pods.items:
        messages.error(request, "Mail server not available.")
        return redirect('list_mail_users')

    smtp_pod = pods.items[0].metadata.name

    # Check if maildir exists using kubectl exec
    check_cmd = [
        "kubectl", "exec", "-i",
        "-n", "kubepanel",
        smtp_pod,
        "--", "sh", "-c", f'test -d "{maildir_path}" && echo "exists"'
    ]
    try:
        result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=30)
        if 'exists' not in result.stdout:
            messages.warning(request, "Mailbox is empty or not yet created.")
            return redirect('list_mail_users')
    except Exception as e:
        messages.error(request, f"Failed to check mailbox: {e}")
        return redirect('list_mail_users')

    # Stream tarball using kubectl exec and subprocess
    tar_cmd = [
        "kubectl", "exec", "-i",
        "-n", "kubepanel",
        smtp_pod,
        "--", "tar", "-czf", "-", "-C", f"/var/mail/vmail/{domain_name}", local_part
    ]

    proc = subprocess.Popen(tar_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def stream_tar():
        """Generator that streams tar output from the pod."""
        try:
            for chunk in iter(lambda: proc.stdout.read(64 * 1024), b""):
                yield chunk
            proc.wait()
        finally:
            proc.stdout.close()
            proc.stderr.close()

    filename = f"{local_part}_{domain_name}_mailbox.tar.gz"
    response = StreamingHttpResponse(
        stream_tar(),
        content_type='application/gzip'
    )
    response['Content-Disposition'] = f'attachment; filename="{filename}"'

    # Log the export
    LogEntry.objects.create(
        content_object=mail_user.domain,
        actor=f"user:{request.user.username}",
        user=request.user,
        level="INFO",
        message=f"Exported mailbox for {mail_user.email}",
        data={"mail_user_id": mail_user.pk, "email": mail_user.email}
    )

    return response


@login_required
def import_mailbox(request, user_id):
    """
    Import mailbox from .tar.gz archive.

    Uploads and extracts archive to mail user's maildir.
    """
    # Get mail user (with ownership check)
    try:
        if request.user.is_superuser:
            mail_user = MailUser.objects.get(pk=user_id)
        else:
            mail_user = MailUser.objects.get(pk=user_id, domain__owner=request.user)
    except MailUser.DoesNotExist:
        messages.error(request, "Email account not found.")
        return redirect('list_mail_users')

    if request.method == 'GET':
        return render(request, 'main/import_mailbox.html', {'mail_user': mail_user})

    # POST: Handle file upload
    archive_file = request.FILES.get('archive_file')
    if not archive_file:
        messages.error(request, "No file uploaded.")
        return redirect('import_mailbox', user_id=user_id)

    # Validate file extension
    filename = archive_file.name
    if not filename.endswith('.tar.gz') and not filename.endswith('.tgz'):
        messages.error(request, "Invalid file type. Please upload a .tar.gz file.")
        return redirect('import_mailbox', user_id=user_id)

    # Check file size
    if archive_file.size > MAX_MAILBOX_UPLOAD_SIZE:
        messages.error(request, "File too large. Maximum size is 5GB.")
        return redirect('import_mailbox', user_id=user_id)

    # Save to temp file
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.tar.gz') as tmp:
            for chunk in archive_file.chunks():
                tmp.write(chunk)
            tmp_path = tmp.name

        # Validate tar archive
        try:
            with tarfile.open(tmp_path, 'r:gz') as tar:
                members = tar.getnames()
                if not members:
                    messages.error(request, "Archive is empty.")
                    return redirect('import_mailbox', user_id=user_id)
        except tarfile.TarError as e:
            messages.error(request, f"Invalid archive: {e}")
            return redirect('import_mailbox', user_id=user_id)

        # Load K8s config and find SMTP pod
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()

        v1 = client.CoreV1Api()
        pods = v1.list_namespaced_pod(
            namespace='kubepanel',
            label_selector='app=smtp'
        )

        if not pods.items:
            messages.error(request, "Mail server not available.")
            return redirect('list_mail_users')

        smtp_pod = pods.items[0].metadata.name
        domain_name = mail_user.domain.domain_name
        local_part = mail_user.local_part
        maildir_path = f"/var/mail/vmail/{domain_name}/{local_part}"

        # Create maildir directory if needed
        mkdir_cmd = [
            "kubectl", "exec", "-n", "kubepanel", smtp_pod,
            "--", "mkdir", "-p", maildir_path
        ]
        subprocess.run(mkdir_cmd, check=True, capture_output=True, timeout=30)

        # Copy archive to pod
        cp_cmd = [
            "kubectl", "cp", tmp_path,
            f"kubepanel/{smtp_pod}:/tmp/mailbox_import.tar.gz"
        ]
        subprocess.run(cp_cmd, check=True, capture_output=True, timeout=300)

        # Extract archive to maildir (strip first component to handle export format)
        extract_cmd = [
            "kubectl", "exec", "-n", "kubepanel", smtp_pod,
            "--", "sh", "-c",
            f'tar -xzf /tmp/mailbox_import.tar.gz -C "{maildir_path}" --strip-components=1 && '
            f'chown -R vmail:vmail "{maildir_path}" && '
            f'rm -f /tmp/mailbox_import.tar.gz'
        ]
        subprocess.run(extract_cmd, check=True, capture_output=True, timeout=300)

        # Log the import
        LogEntry.objects.create(
            content_object=mail_user.domain,
            actor=f"user:{request.user.username}",
            user=request.user,
            level="INFO",
            message=f"Imported mailbox for {mail_user.email}",
            data={"mail_user_id": mail_user.pk, "email": mail_user.email}
        )

        messages.success(request, f"Mailbox imported successfully for {mail_user.email}")
        return redirect('list_mail_users')

    except subprocess.CalledProcessError as e:
        messages.error(request, f"Failed to import mailbox: {e.stderr.decode() if e.stderr else str(e)}")
        return redirect('import_mailbox', user_id=user_id)
    except Exception as e:
        messages.error(request, f"Import failed: {e}")
        return redirect('import_mailbox', user_id=user_id)
    finally:
        # Cleanup temp file
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
