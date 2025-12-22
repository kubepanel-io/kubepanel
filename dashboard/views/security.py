"""
Security, firewall, and IP management views
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator

import os

from dashboard.models import ClusterIP, BlockRule
from .utils import random_string, iterate_input_templates


def manage_ips(request):
    ip_list = ClusterIP.objects.all()
    return render(request, "main/ip_management.html", {"ip_list": ip_list})


def add_ip(request):
    if request.method == "POST":
        ip_address = request.POST.get("ip_address")
        description = request.POST.get("description", "").strip()

        if not ip_address:
            messages.error(request, "IP address is required.")
            return redirect("manage_ips")

        try:
            ClusterIP.objects.create(ip_address=ip_address, description=description)
            messages.success(request, f"IP Address '{ip_address}' added successfully.")
        except Exception as e:
            messages.error(request, f"Error adding IP: {e}")

        return redirect("manage_ips")


def delete_ip(request, ip_id):
    ip = get_object_or_404(ClusterIP, id=ip_id)
    if request.method == "POST":
        ip.delete()
        messages.success(request, f"IP Address '{ip.ip_address}' deleted successfully.")
        return redirect("manage_ips")


@login_required(login_url="/dashboard/")
def blocked_objects(request):
    all_blocks = BlockRule.objects.all().order_by('-created_at')

    paginator = Paginator(all_blocks, 100)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    if request.method == 'POST' and 'generate_rules' in request.POST:
        rules = render_modsec_rules()
        template_dir = "fw_templates/"
        jobid = random_string(5)
        context = {"rules": rules, "jobid": jobid}
        domain_dirname = '/kubepanel/yaml_templates/fwrules'
        try:
            os.mkdir(domain_dirname)
        except:
            print("Can't create directories. Please check debug logs if you think this is an error.")
        iterate_input_templates(template_dir, domain_dirname, context)
        return redirect("blocked_objects")

    return render(request, 'main/blocked_objects.html', {'page_obj': page_obj})


@login_required(login_url="/dashboard/")
def block_entry(request, vhost, x_forwarded_for, path):
    if request.method == 'POST':
        block_ip = bool(request.POST.get('block_ip'))
        block_vhost = bool(request.POST.get('block_vhost'))
        block_path = bool(request.POST.get('block_path'))

        BlockRule.objects.create(
            ip_address=x_forwarded_for if block_ip else None,
            vhost=vhost if block_vhost else None,
            path=path if block_path else None,
            block_ip=block_ip,
            block_vhost=block_vhost,
            block_path=block_path
        )
        return redirect("blocked_objects")
    else:
        context = {
            'vhost': vhost,
            'x_forwarded_for': x_forwarded_for,
            'path': path
        }
        return render(request, 'main/block_entry.html', context)


def generate_modsec_rule(br: BlockRule) -> str:
    conditions = []
    if br.block_ip and br.ip_address:
        conditions.append(("REMOTE_ADDR", br.ip_address))
    if br.block_vhost and br.vhost:
        conditions.append(("SERVER_NAME", br.vhost))
    if br.block_path and br.path:
        conditions.append(("REQUEST_URI", br.path))

    if not conditions:
        return ""

    rule_id = 10000 + br.pk
    msg_parts = []

    if br.block_ip:
        msg_parts.append("IP")
    if br.block_vhost:
        msg_parts.append("vhost")
    if br.block_path:
        msg_parts.append("path")
    msg_string = f"Blocking {', '.join(msg_parts)}"

    if len(conditions) == 1:
        var, val = conditions[0]
        return (
            f'SecRule {var} "@streq {val}" '
            f'"phase:1,id:{rule_id},deny,msg:\\"{msg_string}\\""'
        )

    rule_lines = []

    first_var, first_val = conditions[0]
    rule_lines.append(
        f'SecRule {first_var} "@streq {first_val}" '
        f'"phase:1,id:{rule_id},deny,chain,msg:\\"{msg_string}\\""'
    )

    for var, val in conditions[1:-1]:
        rule_lines.append(f'    SecRule {var} "@streq {val}" "chain"')

    last_var, last_val = conditions[-1]
    rule_lines.append(f'    SecRule {last_var} "@streq {last_val}"')

    return "\n".join(rule_lines)


def render_modsec_rules() -> str:
    block_rules = BlockRule.objects.all()
    rules_output = []

    for br in block_rules:
        rule_str = generate_modsec_rule(br)
        if rule_str:
            rules_output.append(rule_str)

    return rules_output


@login_required
def firewall_rule_delete(request, pk):
    block = get_object_or_404(BlockRule, pk=pk)

    if request.method == 'POST':
        block.delete()
        messages.success(request, f"Deleted rule #{pk}.")
    return redirect('blocked_objects')
