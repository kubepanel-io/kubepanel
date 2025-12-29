"""
Collect metrics from Kubernetes metrics-server and ingress logs.

Run this command every 5 minutes via a Kubernetes CronJob:
    python manage.py collect_metrics

Data sources:
- CPU/Memory: Kubernetes metrics-server API
- HTTP metrics: Ingress-nginx JSON logs
"""
import os
import json
import logging
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
import requests

from dashboard.models import Domain, DomainMetric

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Collect metrics from Kubernetes for all active domains'

    def add_arguments(self, parser):
        parser.add_argument(
            '--domain',
            type=str,
            help='Collect metrics for a specific domain only',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Print metrics without saving to database',
        )

    def handle(self, *args, **options):
        self.dry_run = options.get('dry_run', False)
        specific_domain = options.get('domain')

        # Get K8s auth
        try:
            self.k8s_host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
            self.k8s_port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
            self.token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
            self.ca_cert_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

            if os.path.exists(self.token_path):
                with open(self.token_path, 'r') as f:
                    self.k8s_token = f.read().strip()
            else:
                self.stdout.write(self.style.WARNING('Not running in K8s cluster, using mock data'))
                self.k8s_token = None
        except Exception as e:
            self.stdout.write(self.style.WARNING(f'K8s auth failed: {e}, using mock data'))
            self.k8s_token = None

        # Get domains to process
        if specific_domain:
            domains = Domain.objects.filter(domain_name=specific_domain)
        else:
            domains = Domain.objects.all()

        timestamp = timezone.now().replace(second=0, microsecond=0)
        collected = 0

        for domain in domains:
            try:
                metrics = self.collect_domain_metrics(domain, timestamp)
                if metrics:
                    if self.dry_run:
                        self.stdout.write(f"{domain.domain_name}: {metrics}")
                    else:
                        DomainMetric.objects.create(**metrics)
                        collected += 1
            except Exception as e:
                logger.error(f"Error collecting metrics for {domain.domain_name}: {e}")
                self.stdout.write(self.style.ERROR(f"Error for {domain.domain_name}: {e}"))

        self.stdout.write(self.style.SUCCESS(f'Collected metrics for {collected} domains'))

    def collect_domain_metrics(self, domain, timestamp):
        """Collect all metrics for a single domain."""
        namespace = domain.namespace

        # Get resource metrics from metrics-server
        cpu_metrics = self.get_pod_metrics(namespace)

        # Get HTTP metrics from ingress logs
        http_metrics = self.get_http_metrics(domain.domain_name)

        return {
            'domain': domain,
            'timestamp': timestamp,
            'period': '5min',
            # CPU/Memory
            'cpu_millicores': cpu_metrics.get('cpu_millicores', 0),
            'cpu_limit_millicores': domain.cpu_limit,
            'memory_bytes': cpu_metrics.get('memory_bytes', 0),
            'memory_limit_bytes': domain.mem_limit * 1024 * 1024,  # Convert MB to bytes
            # HTTP
            'http_requests': http_metrics.get('total', 0),
            'http_2xx': http_metrics.get('status_2xx', 0),
            'http_3xx': http_metrics.get('status_3xx', 0),
            'http_4xx': http_metrics.get('status_4xx', 0),
            'http_5xx': http_metrics.get('status_5xx', 0),
            'avg_latency_ms': http_metrics.get('avg_latency_ms', 0),
            'bytes_in': http_metrics.get('bytes_in', 0),
            'bytes_out': http_metrics.get('bytes_out', 0),
        }

    def get_pod_metrics(self, namespace):
        """Get CPU/memory metrics from metrics-server API."""
        if not self.k8s_token:
            return {'cpu_millicores': 0, 'memory_bytes': 0}

        try:
            headers = {
                "Authorization": f"Bearer {self.k8s_token}",
                "Content-Type": "application/json"
            }

            # Use metrics.k8s.io API
            url = f"https://{self.k8s_host}:{self.k8s_port}/apis/metrics.k8s.io/v1beta1/namespaces/{namespace}/pods"
            response = requests.get(url, headers=headers, verify=self.ca_cert_path, timeout=10)

            if response.status_code == 404:
                # Namespace might not exist or no pods running
                return {'cpu_millicores': 0, 'memory_bytes': 0}

            response.raise_for_status()
            data = response.json()

            total_cpu = 0
            total_memory = 0

            for pod in data.get('items', []):
                for container in pod.get('containers', []):
                    usage = container.get('usage', {})

                    # Parse CPU (format: "123456n" for nanocores or "123m" for millicores)
                    cpu_str = usage.get('cpu', '0')
                    if cpu_str.endswith('n'):
                        total_cpu += int(cpu_str[:-1]) / 1000000  # nanocores to millicores
                    elif cpu_str.endswith('m'):
                        total_cpu += int(cpu_str[:-1])
                    else:
                        total_cpu += int(cpu_str) * 1000  # cores to millicores

                    # Parse Memory (format: "123456Ki" or "123Mi")
                    mem_str = usage.get('memory', '0')
                    if mem_str.endswith('Ki'):
                        total_memory += int(mem_str[:-2]) * 1024
                    elif mem_str.endswith('Mi'):
                        total_memory += int(mem_str[:-2]) * 1024 * 1024
                    elif mem_str.endswith('Gi'):
                        total_memory += int(mem_str[:-2]) * 1024 * 1024 * 1024
                    else:
                        total_memory += int(mem_str)

            return {
                'cpu_millicores': int(total_cpu),
                'memory_bytes': int(total_memory)
            }

        except Exception as e:
            logger.warning(f"Failed to get metrics for {namespace}: {e}")
            return {'cpu_millicores': 0, 'memory_bytes': 0}

    def get_http_metrics(self, domain_name):
        """Get HTTP metrics from ingress-nginx logs (last 5 minutes)."""
        if not self.k8s_token:
            return self._empty_http_metrics()

        try:
            headers = {
                "Authorization": f"Bearer {self.k8s_token}",
                "Content-Type": "application/json"
            }

            # Get ingress pods
            namespace = "ingress"
            url = f"https://{self.k8s_host}:{self.k8s_port}/api/v1/namespaces/{namespace}/pods"
            response = requests.get(url, headers=headers, verify=self.ca_cert_path, timeout=10)
            response.raise_for_status()
            pods = response.json().get('items', [])

            metrics = {
                'total': 0,
                'status_2xx': 0,
                'status_3xx': 0,
                'status_4xx': 0,
                'status_5xx': 0,
                'latency_sum': 0,
                'bytes_in': 0,
                'bytes_out': 0,
            }

            for pod in pods:
                pod_name = pod['metadata']['name']
                # Get logs from last 5 minutes
                log_url = f"https://{self.k8s_host}:{self.k8s_port}/api/v1/namespaces/{namespace}/pods/{pod_name}/log?sinceSeconds=300"
                log_response = requests.get(log_url, headers=headers, verify=self.ca_cert_path, timeout=30)

                if log_response.status_code != 200:
                    continue

                for line in log_response.text.splitlines():
                    if not line.strip():
                        continue
                    try:
                        log_entry = json.loads(line)

                        # Check if this request is for our domain
                        host = log_entry.get('host', '')
                        if domain_name not in host:
                            continue

                        # Skip static files for request count
                        uri = log_entry.get('uri', '')
                        if self._is_static_file(uri):
                            continue

                        metrics['total'] += 1

                        # Status code
                        status = int(log_entry.get('status', 0))
                        if 200 <= status < 300:
                            metrics['status_2xx'] += 1
                        elif 300 <= status < 400:
                            metrics['status_3xx'] += 1
                        elif 400 <= status < 500:
                            metrics['status_4xx'] += 1
                        elif 500 <= status < 600:
                            metrics['status_5xx'] += 1

                        # Latency
                        try:
                            latency = float(log_entry.get('request_time', 0)) * 1000  # to ms
                            metrics['latency_sum'] += latency
                        except (ValueError, TypeError):
                            pass

                        # Bytes
                        try:
                            metrics['bytes_in'] += int(log_entry.get('request_length', 0))
                            metrics['bytes_out'] += int(log_entry.get('bytes_sent', 0))
                        except (ValueError, TypeError):
                            pass

                    except json.JSONDecodeError:
                        continue

            # Calculate average latency
            avg_latency = 0
            if metrics['total'] > 0:
                avg_latency = metrics['latency_sum'] / metrics['total']

            return {
                'total': metrics['total'],
                'status_2xx': metrics['status_2xx'],
                'status_3xx': metrics['status_3xx'],
                'status_4xx': metrics['status_4xx'],
                'status_5xx': metrics['status_5xx'],
                'avg_latency_ms': round(avg_latency, 2),
                'bytes_in': metrics['bytes_in'],
                'bytes_out': metrics['bytes_out'],
            }

        except Exception as e:
            logger.warning(f"Failed to get HTTP metrics for {domain_name}: {e}")
            return self._empty_http_metrics()

    def _empty_http_metrics(self):
        return {
            'total': 0,
            'status_2xx': 0,
            'status_3xx': 0,
            'status_4xx': 0,
            'status_5xx': 0,
            'avg_latency_ms': 0,
            'bytes_in': 0,
            'bytes_out': 0,
        }

    def _is_static_file(self, uri):
        """Check if URI is for a static file."""
        static_extensions = (
            '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico',
            '.svg', '.woff', '.woff2', '.ttf', '.eot', '.map'
        )
        return uri.lower().endswith(static_extensions)
