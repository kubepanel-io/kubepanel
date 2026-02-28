from django.core.management.base import BaseCommand, CommandError
from dashboard.models import Domain
import os, requests

class Command(BaseCommand):
    help = "Fetch each domain's Pod statuses from the K8s API and store in domain.status"

    def handle(self, *args, **kwargs):
        domains = Domain.objects.all()
        host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        ca_cert_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

        with open(token_path, 'r') as f:
            token = f.read().strip()
        headers = {"Authorization": f"Bearer {token}"}

        for domain in domains:
            namespace = domain.domain_name.replace(".", "-")
            url = f"https://{host}:{port}/api/v1/namespaces/{namespace}/pods"

            try:
                resp = requests.get(url, headers=headers, verify=ca_cert_path)
                resp.raise_for_status()
            except requests.RequestException as e:
                self.stderr.write(f"Error fetching pods for {namespace}: {e}")
                domain.status = "Error"
                domain.save()
                continue

            items = resp.json().get("items", [])

            if not items:
                domain.status = "Not running"
                domain.save()
                continue

            lines = []
            # first line: the node of the first pod
            first_node = items[0].get("spec", {}).get("nodeName", "<unknown-node>")
            lines.append(first_node)

            for item in items:
                meta = item.get("metadata", {}) or {}
                labels = meta.get("labels", {}) or {}

                # Skip any pod without an 'app' label
                if "app" not in labels:
                    continue

                app_label = labels["app"]
                ann = meta.get("annotations", {}) or {}
                kp_status = ann.get("kubepanel.status", "<no-status>")
                phase = item.get("status", {}).get("phase", "<no-phase>")

                lines.append(f"{app_label}:{kp_status}, {phase}")

            domain.status = "<br>".join(lines)
            domain.save()

