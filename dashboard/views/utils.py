"""
Utility functions and base classes for views
"""
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin

import os
import random
import string
import geoip2.database

GEOIP_DB_PATH = "/kubepanel/GeoLite2-Country.mmdb"
EXCLUDED_EXTENSIONS = [".js", ".css", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map"]


class SuperuserRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    def test_func(self):
        return self.request.user.is_superuser


def random_string(num):
    char_set = string.ascii_lowercase + string.digits
    rndstring = ''.join(random.sample(char_set*6, num))
    return rndstring


def get_country_info(ip_address):
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.country(ip_address)
            country_name = response.country.name
            country_code = response.country.iso_code.lower()
            return {
                "country_name": country_name,
                "flag_url": f"https://flagcdn.com/w40/{country_code}.png",
            }
    except geoip2.errors.AddressNotFoundError:
        return {"country_name": "Unknown", "flag_url": ""}
    except Exception as e:
        print(f"Error resolving IP {ip_address}: {e}")
        return {"country_name": "Unknown", "flag_url": ""}


def is_static_file(log_entry):
    path = log_entry.get("path", "")
    return any(path.endswith(ext) for ext in EXCLUDED_EXTENSIONS)


def get_client_ip(request):
    """Get the real IP address of the client, accounting for proxies"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', 'Unknown')
    return ip


def get_user_agent(request):
    """Get the user agent string"""
    return request.META.get('HTTP_USER_AGENT', 'Unknown')


def _load_k8s_auth():
    """Load Kubernetes authentication from service account"""
    host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    ca_cert = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

    try:
        token = open(token_path).read().strip()
    except FileNotFoundError:
        raise RuntimeError("Kubernetes token file not found")

    base = f"https://{host}:{port}"
    headers = {
        "Authorization": f"Bearer {token}",
    }
    return base, headers, ca_cert
