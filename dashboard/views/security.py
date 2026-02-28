"""
Security and IP management views
"""
import logging

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages

from dashboard.models import ClusterIP

logger = logging.getLogger("django")


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
