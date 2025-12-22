"""
Mail user and alias management views
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required

from dashboard.models import Domain, MailUser, MailAlias
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
