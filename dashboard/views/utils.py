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

# ISO 3166-1 alpha-2 country codes with names for WAF dropdowns
COUNTRIES = [
    ("AF", "Afghanistan"),
    ("AL", "Albania"),
    ("DZ", "Algeria"),
    ("AR", "Argentina"),
    ("AU", "Australia"),
    ("AT", "Austria"),
    ("BD", "Bangladesh"),
    ("BY", "Belarus"),
    ("BE", "Belgium"),
    ("BR", "Brazil"),
    ("BG", "Bulgaria"),
    ("CA", "Canada"),
    ("CL", "Chile"),
    ("CN", "China"),
    ("CO", "Colombia"),
    ("HR", "Croatia"),
    ("CU", "Cuba"),
    ("CZ", "Czech Republic"),
    ("DK", "Denmark"),
    ("EG", "Egypt"),
    ("EE", "Estonia"),
    ("FI", "Finland"),
    ("FR", "France"),
    ("DE", "Germany"),
    ("GR", "Greece"),
    ("HK", "Hong Kong"),
    ("HU", "Hungary"),
    ("IN", "India"),
    ("ID", "Indonesia"),
    ("IR", "Iran"),
    ("IQ", "Iraq"),
    ("IE", "Ireland"),
    ("IL", "Israel"),
    ("IT", "Italy"),
    ("JP", "Japan"),
    ("KZ", "Kazakhstan"),
    ("KE", "Kenya"),
    ("KP", "North Korea"),
    ("KR", "South Korea"),
    ("LV", "Latvia"),
    ("LT", "Lithuania"),
    ("MY", "Malaysia"),
    ("MX", "Mexico"),
    ("MD", "Moldova"),
    ("NL", "Netherlands"),
    ("NZ", "New Zealand"),
    ("NG", "Nigeria"),
    ("NO", "Norway"),
    ("PK", "Pakistan"),
    ("PH", "Philippines"),
    ("PL", "Poland"),
    ("PT", "Portugal"),
    ("RO", "Romania"),
    ("RU", "Russia"),
    ("SA", "Saudi Arabia"),
    ("RS", "Serbia"),
    ("SG", "Singapore"),
    ("SK", "Slovakia"),
    ("SI", "Slovenia"),
    ("ZA", "South Africa"),
    ("ES", "Spain"),
    ("SE", "Sweden"),
    ("CH", "Switzerland"),
    ("SY", "Syria"),
    ("TW", "Taiwan"),
    ("TH", "Thailand"),
    ("TR", "Turkey"),
    ("UA", "Ukraine"),
    ("AE", "United Arab Emirates"),
    ("GB", "United Kingdom"),
    ("US", "United States"),
    ("VN", "Vietnam"),
]


def get_countries_list():
    """Return the list of countries for WAF dropdowns."""
    return COUNTRIES


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
