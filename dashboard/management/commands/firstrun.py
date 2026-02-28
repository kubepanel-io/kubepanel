from django.core.management.base import BaseCommand
from dashboard.models import ClusterIP
import os


class Command(BaseCommand):
    help = 'First-run initialization: creates ClusterIPs from node IP environment variables'

    def handle(self, *args, **kwargs):
        # Create ClusterIPs from environment variables
        ip_envs = {
            'NODE_1_IP': 'Node 1',
            'NODE_2_IP': 'Node 2',
            'NODE_3_IP': 'Node 3',
        }
        for env_var, desc in ip_envs.items():
            ip = os.getenv(env_var)
            if not ip:
                self.stderr.write(f"Warning: {env_var} is not set; skipping.")
                continue
            obj, created = ClusterIP.objects.get_or_create(
                ip_address=ip,
                defaults={'description': desc}
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f"Created ClusterIP {ip} ({desc})"))
            else:
                self.stdout.write(f"ClusterIP {ip} already exists; skipped.")

        self.stdout.write(self.style.SUCCESS("Firstrun completed."))
