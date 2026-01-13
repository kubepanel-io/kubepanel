"""
Mail user and alias management views
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import StreamingHttpResponse

from kubernetes import client, config
from kubernetes.stream import stream

from dashboard.models import Domain, MailUser, MailAlias, LogEntry
from dashboard.forms import MailUserForm, MailAliasForm


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

    Streams tarball directly from SMTP pod to user.
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

    # Check if maildir exists
    check_cmd = ['sh', '-c', f'test -d "{maildir_path}" && echo "exists"']
    try:
        resp = stream(
            v1.connect_get_namespaced_pod_exec,
            smtp_pod, 'kubepanel',
            command=check_cmd,
            stderr=True, stdin=False, stdout=True, tty=False
        )
        if 'exists' not in resp:
            messages.warning(request, "Mailbox is empty or not yet created.")
            return redirect('list_mail_users')
    except Exception as e:
        messages.error(request, f"Failed to check mailbox: {e}")
        return redirect('list_mail_users')

    # Stream tarball
    tar_cmd = ['tar', '-czf', '-', '-C', f'/var/mail/vmail/{domain_name}', local_part]

    def stream_tar():
        """Generator that streams tar output from the pod."""
        resp = stream(
            v1.connect_get_namespaced_pod_exec,
            smtp_pod, 'kubepanel',
            command=tar_cmd,
            stderr=False, stdin=False, stdout=True, tty=False,
            _preload_content=False
        )
        # Read from websocket while connection is open
        while resp.is_open():
            resp.update(timeout=5)
            if resp.peek_stdout():
                chunk = resp.read_stdout()
                if chunk:
                    yield chunk.encode('latin-1') if isinstance(chunk, str) else chunk
        # Read any remaining data
        if resp.peek_stdout():
            chunk = resp.read_stdout()
            if chunk:
                yield chunk.encode('latin-1') if isinstance(chunk, str) else chunk
        resp.close()

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
