"""
Collect system health status from Kubernetes cluster components.

Run this command every 5 minutes via a sidecar container:
    while true; do python manage.py collect_health; sleep 300; done

Components checked:
- Linstor: Volume integrity via REST API
- Mail Queue: Postfix queue size via 'postqueue -p'
- MariaDB: Database health via TCP connection
- SMTP Storage: Per-domain email storage usage
- MariaDB Storage: Per-domain database storage usage
- Storage Notifications: Send email alerts when storage usage exceeds thresholds

Note: PVC/disk storage is collected by collect_metrics command (DomainMetric.storage_bytes).
Storage notifications combine PVC (from DomainMetric) + email + database storage.
"""
import os
import re
import logging
import smtplib
from datetime import timedelta
from email.mime.text import MIMEText

from django.core.management.base import BaseCommand
from django.conf import settings
from django.contrib.auth.models import User

from kubernetes import client, config
from kubernetes.stream import stream
from kubernetes.client.rest import ApiException

from django.utils import timezone

from dashboard.models import (
    Domain, DomainMetric, DomainStorageUsage, SystemHealthStatus, SystemSettings,
    StorageNotificationLog
)

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Collect system health status from Kubernetes cluster components'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Print health status without saving to database',
        )
        parser.add_argument(
            '--component',
            type=str,
            choices=['linstor', 'mail_queue', 'mariadb', 'smtp_storage', 'mariadb_storage', 'storage_notifications'],
            help='Check only a specific component',
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed output for debugging',
        )

    def handle(self, *args, **options):
        self.dry_run = options.get('dry_run', False)
        self.verbose = options.get('verbose', False)
        specific_component = options.get('component')
        self.db_available = True

        # Load K8s config
        try:
            config.load_incluster_config()
        except config.ConfigException:
            try:
                config.load_kube_config()
            except config.ConfigException:
                self.stdout.write(self.style.WARNING('K8s config not available'))
                return

        self.core_v1 = client.CoreV1Api()

        # Try to load settings from DB, use defaults if DB unavailable
        try:
            self.system_settings = SystemSettings.get_settings()
        except Exception as e:
            self.db_available = False
            self.stdout.write(self.style.WARNING(
                f"Database unavailable, using defaults (results won't be saved)"
            ))
            logger.warning(f"Database unavailable, using default settings: {e}")
            # Create a mock settings object with defaults
            self.system_settings = type('MockSettings', (), {
                'mail_queue_warning_threshold': 50,
                'mail_queue_error_threshold': 100,
                'health_check_email_enabled': False,
            })()

        # Components to check (storage_notifications runs separately after storage collection)
        components = ['linstor', 'mail_queue', 'mariadb', 'smtp_storage', 'mariadb_storage']
        if specific_component:
            if specific_component == 'storage_notifications':
                # Only run storage notifications
                self.check_storage_notifications()
                self.stdout.write(self.style.SUCCESS('Storage notifications check completed'))
                return
            components = [specific_component]

        results = []
        for component in components:
            try:
                if component == 'linstor':
                    result = self.check_linstor()
                elif component == 'mail_queue':
                    result = self.check_mail_queue()
                elif component == 'mariadb':
                    result = self.check_mariadb()
                elif component == 'smtp_storage':
                    result = self.check_smtp_storage()
                elif component == 'mariadb_storage':
                    result = self.check_mariadb_storage()

                results.append(result)

                if self.dry_run:
                    self.stdout.write(
                        f"{component}: {result['status']} - {result['message']}"
                    )
                else:
                    self.save_status(result)

            except Exception as e:
                logger.error(f"Error checking {component}: {e}")
                error_result = {
                    'component': component,
                    'status': 'error',
                    'message': f"Check failed: {e}",
                    'details': {'error': str(e)},
                }
                results.append(error_result)
                if not self.dry_run:
                    self.save_status(error_result)

        # Send system health alerts if needed
        if not self.dry_run:
            self.process_alerts(results)

        # Sync PVC storage from DomainMetric to DomainStorageUsage
        if not specific_component or specific_component in ('smtp_storage', 'mariadb_storage'):
            self.sync_pvc_storage()

        # Process storage notifications (after all storage data is collected)
        if not specific_component or specific_component in ('smtp_storage', 'mariadb_storage'):
            self.check_storage_notifications()

        self.stdout.write(self.style.SUCCESS(f'Health check completed for {len(results)} components'))

    def check_linstor(self):
        """
        Check Linstor volume integrity via REST API.

        Fetches /v1/view/resources from Linstor controller and checks disk_state.
        Valid states: UpToDate, Diskless, TieBreaker
        """
        import urllib.request
        import json

        api_url = 'http://linstor-controller.piraeus-datastore.svc.cluster.local:3370/v1/view/resources'

        try:
            req = urllib.request.Request(api_url, headers={'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))

            if self.verbose:
                self.stdout.write(f"Linstor API returned {len(data)} resources")

            return self.parse_linstor_api_response(data)

        except urllib.error.URLError as e:
            return {
                'component': 'linstor',
                'status': 'error',
                'message': f'Cannot reach Linstor API: {e.reason}',
                'details': {'url': api_url, 'error': str(e)},
            }
        except json.JSONDecodeError as e:
            return {
                'component': 'linstor',
                'status': 'error',
                'message': f'Invalid JSON from Linstor API: {e}',
                'details': {'url': api_url},
            }
        except Exception as e:
            return {
                'component': 'linstor',
                'status': 'error',
                'message': f'Linstor check failed: {e}',
                'details': {'error': str(e)},
            }

    def parse_linstor_api_response(self, data):
        """Parse Linstor REST API response and check volume states."""
        valid_states = {'UpToDate', 'Diskless', 'TieBreaker'}
        error_states = []
        total_volumes = 0
        healthy_volumes = 0

        for resource in data:
            resource_name = resource.get('name', 'unknown')
            node_name = resource.get('node_name', 'unknown')
            volumes = resource.get('volumes', [])

            for volume in volumes:
                total_volumes += 1
                state_info = volume.get('state', {})
                disk_state = state_info.get('disk_state', 'Unknown')

                if self.verbose:
                    self.stdout.write(f"  {resource_name}@{node_name}: {disk_state}")

                if disk_state in valid_states:
                    healthy_volumes += 1
                else:
                    error_states.append(f"{resource_name}@{node_name}: {disk_state}")

        if total_volumes == 0:
            return {
                'component': 'linstor',
                'status': 'warning',
                'message': 'No volumes found',
                'details': {'total': 0, 'healthy': 0},
            }

        if error_states:
            return {
                'component': 'linstor',
                'status': 'error',
                'message': f'{len(error_states)} volumes in unhealthy state',
                'details': {
                    'total': total_volumes,
                    'healthy': healthy_volumes,
                    'errors': error_states[:10],  # Limit to first 10
                },
            }

        return {
            'component': 'linstor',
            'status': 'healthy',
            'message': f'All {total_volumes} volumes healthy',
            'details': {'total': total_volumes, 'healthy': healthy_volumes},
        }

    def check_mail_queue(self):
        """
        Check Postfix mail queue size.

        Runs 'postqueue -p | tail -1' in smtp pod and parses the output.
        Output: "Mail queue is empty" or "-- X Kbytes in N Requests."
        """
        namespace = 'kubepanel'
        label_selector = 'app=smtp'

        try:
            pods = self.core_v1.list_namespaced_pod(
                namespace=namespace,
                label_selector=label_selector
            ).items

            running_pods = [p for p in pods if p.status.phase == 'Running']
            if not running_pods:
                return {
                    'component': 'mail_queue',
                    'status': 'error',
                    'message': 'SMTP pod not running',
                    'details': {'namespace': namespace, 'selector': label_selector},
                }

            pod_name = running_pods[0].metadata.name

            # Execute postqueue -p | tail -1
            result = stream(
                self.core_v1.connect_get_namespaced_pod_exec,
                name=pod_name,
                namespace=namespace,
                command=['sh', '-c', 'postqueue -p | tail -1'],
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False,
                _preload_content=True
            )

            return self.parse_mail_queue_output(result.strip())

        except ApiException as e:
            return {
                'component': 'mail_queue',
                'status': 'error',
                'message': f'API error: {e.reason}',
                'details': {'status': e.status},
            }

    def parse_mail_queue_output(self, output):
        """Parse postqueue output and determine queue count."""
        queue_count = 0

        if 'empty' in output.lower():
            queue_count = 0
        else:
            # Parse "-- X Kbytes in N Requests."
            match = re.search(r'(\d+)\s+Requests?', output)
            if match:
                queue_count = int(match.group(1))

        # Determine status based on thresholds
        warning_threshold = self.system_settings.mail_queue_warning_threshold
        error_threshold = self.system_settings.mail_queue_error_threshold

        if queue_count >= error_threshold:
            status = 'error'
            message = f'{queue_count} messages queued (threshold: {error_threshold})'
        elif queue_count >= warning_threshold:
            status = 'warning'
            message = f'{queue_count} messages queued (threshold: {warning_threshold})'
        else:
            status = 'healthy'
            message = f'{queue_count} messages in queue'

        return {
            'component': 'mail_queue',
            'status': status,
            'message': message,
            'details': {
                'queue_count': queue_count,
                'warning_threshold': warning_threshold,
                'error_threshold': error_threshold,
            },
        }

    def check_mariadb(self):
        """
        Check MariaDB health.

        Tests TCP connectivity to mariadb service on port 3306.
        This doesn't require authentication credentials.
        """
        import socket

        # MariaDB service in kubepanel namespace
        host = 'mariadb.kubepanel.svc.cluster.local'
        port = 3306
        timeout = 5

        try:
            # Try TCP connection to MariaDB service
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()

            if result == 0:
                return {
                    'component': 'mariadb',
                    'status': 'healthy',
                    'message': 'MariaDB is responding on port 3306',
                    'details': {'host': host, 'port': port},
                }
            else:
                return {
                    'component': 'mariadb',
                    'status': 'error',
                    'message': f'Cannot connect to MariaDB (error code: {result})',
                    'details': {'host': host, 'port': port, 'error_code': result},
                }

        except socket.timeout:
            return {
                'component': 'mariadb',
                'status': 'error',
                'message': 'Connection to MariaDB timed out',
                'details': {'host': host, 'port': port, 'timeout': timeout},
            }
        except socket.gaierror as e:
            return {
                'component': 'mariadb',
                'status': 'error',
                'message': f'DNS resolution failed: {e}',
                'details': {'host': host, 'error': str(e)},
            }
        except Exception as e:
            return {
                'component': 'mariadb',
                'status': 'error',
                'message': f'Connection error: {e}',
                'details': {'host': host, 'error': str(e)},
            }

    def save_status(self, result):
        """Save health status to database."""
        if not self.db_available:
            logger.warning(f"Cannot save {result['component']} status: database unavailable")
            return

        try:
            # Get or create status record for this component
            status_obj, created = SystemHealthStatus.objects.get_or_create(
                component=result['component'],
                defaults={
                    'status': result['status'],
                    'message': result['message'],
                    'details': result.get('details', {}),
                }
            )

            if not created:
                # Check if status changed from unhealthy to healthy
                if status_obj.status in ('warning', 'error') and result['status'] == 'healthy':
                    status_obj.alert_sent = False  # Reset alert flag

                status_obj.status = result['status']
                status_obj.message = result['message']
                status_obj.details = result.get('details', {})
                status_obj.save()
        except Exception as e:
            logger.error(f"Failed to save {result['component']} status: {e}")

    def process_alerts(self, results):
        """Send email alerts for warning/error statuses."""
        # Check if alerts are enabled (use env var as fallback when DB unavailable)
        alerts_enabled = self.system_settings.health_check_email_enabled
        env_alert_email = os.environ.get('KUBEPANEL_ALERT_EMAIL', '')

        if self.verbose:
            self.stdout.write(f"[Alerts] DB available: {self.db_available}")
            self.stdout.write(f"[Alerts] alerts_enabled (from settings): {alerts_enabled}")
            self.stdout.write(f"[Alerts] KUBEPANEL_ALERT_EMAIL env var: '{env_alert_email}'")

        if not alerts_enabled and not env_alert_email:
            if self.verbose:
                self.stdout.write("[Alerts] Skipping - alerts disabled and no env var set")
            return

        # Collect components that need alerts
        alert_components = []
        for result in results:
            if result['status'] in ('warning', 'error'):
                if self.db_available:
                    # Check if alert already sent (only when DB available)
                    try:
                        status_obj = SystemHealthStatus.objects.get(component=result['component'])
                        if not status_obj.alert_sent:
                            alert_components.append(result)
                            status_obj.alert_sent = True
                            status_obj.save()
                    except SystemHealthStatus.DoesNotExist:
                        alert_components.append(result)
                    except Exception as e:
                        logger.error(f"Error checking alert status for {result['component']}: {e}")
                        alert_components.append(result)
                else:
                    # DB unavailable - always send alert (can't track if already sent)
                    alert_components.append(result)

        if self.verbose:
            self.stdout.write(f"[Alerts] Components needing alerts: {len(alert_components)}")
            for comp in alert_components:
                self.stdout.write(f"  - {comp['component']}: {comp['status']}")

        if not alert_components:
            if self.verbose:
                self.stdout.write("[Alerts] No components need alerting")
            return

        # Build email content
        subject = '[KubePanel Alert] System Health Issue Detected'
        body_lines = ['The following system health issues have been detected:\n']

        for comp in alert_components:
            body_lines.append(f"Component: {comp['component'].replace('_', ' ').title()}")
            body_lines.append(f"Status: {comp['status'].upper()}")
            body_lines.append(f"Message: {comp['message']}")
            body_lines.append('')

        body_lines.append('---')
        body_lines.append('This is an automated alert from KubePanel.')
        body_lines.append('Check the Nodes page for details.')

        body = '\n'.join(body_lines)

        # Get recipient emails
        recipient_emails = []

        # Try to get superuser emails from DB
        if self.db_available:
            try:
                superusers = User.objects.filter(is_superuser=True, is_active=True)
                recipient_emails = [u.email for u in superusers if u.email]
            except Exception as e:
                logger.error(f"Failed to fetch superuser emails: {e}")

        # Fallback to environment variable (or use as additional recipients)
        fallback_emails = os.environ.get('KUBEPANEL_ALERT_EMAIL', '')
        if fallback_emails:
            for email in fallback_emails.split(','):
                email = email.strip()
                if email and email not in recipient_emails:
                    recipient_emails.append(email)

        if self.verbose:
            self.stdout.write(f"[Alerts] Recipient emails: {recipient_emails}")

        if not recipient_emails:
            logger.warning('No recipient emails configured for health alerts')
            if self.verbose:
                self.stdout.write("[Alerts] No recipients - skipping email")
            return

        # Get KUBEPANEL_DOMAIN from settings (ALLOWED_HOSTS)
        kubepanel_domain = settings.ALLOWED_HOSTS[0] if settings.ALLOWED_HOSTS else 'localhost'
        from_email = f'noreply@{kubepanel_domain}'
        from_name = 'KubePanel'
        formatted_from = f'{from_name} <{from_email}>'

        if self.verbose:
            self.stdout.write(f"[Alerts] From address: {formatted_from}")

        # Send using internal SMTP (no auth needed - kubepanel pods are in trusted mynetworks)
        import smtplib
        from email.mime.text import MIMEText

        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = formatted_from
        msg['To'] = ', '.join(recipient_emails)

        try:
            # Use headless service (smtp-internal) to bypass kube-proxy SNAT
            # This ensures direct pod-to-pod communication, preserving source IP
            if self.verbose:
                self.stdout.write(f"[Alerts] Connecting to smtp-internal.kubepanel.svc.cluster.local:25")
            with smtplib.SMTP('smtp-internal.kubepanel.svc.cluster.local', 25, timeout=30) as server:
                server.sendmail(from_email, recipient_emails, msg.as_string())
            logger.info(f'Health alert sent to {len(recipient_emails)} recipients')
            if self.verbose:
                self.stdout.write(f"[Alerts] Email sent successfully to {len(recipient_emails)} recipients")
        except Exception as e:
            logger.error(f'Failed to send health alert email: {e}')
            if self.verbose:
                self.stdout.write(f"[Alerts] Failed to send email: {e}")

    def check_smtp_storage(self):
        """
        Collect storage usage from SMTP pod for all domains.

        Runs 'du -sb /var/mail/vmail/*' and parses per-domain sizes.
        Also collects PVC total size for summary.
        """
        namespace = 'kubepanel'
        label_selector = 'app=smtp'

        try:
            pods = self.core_v1.list_namespaced_pod(
                namespace=namespace,
                label_selector=label_selector
            ).items

            running_pods = [p for p in pods if p.status.phase == 'Running']
            if not running_pods:
                return {
                    'component': 'smtp_storage',
                    'status': 'error',
                    'message': 'SMTP pod not running',
                    'details': {'namespace': namespace, 'selector': label_selector},
                }

            pod_name = running_pods[0].metadata.name

            # Get per-domain storage usage
            result = stream(
                self.core_v1.connect_get_namespaced_pod_exec,
                name=pod_name,
                namespace=namespace,
                command=['sh', '-c', 'du -sb /var/mail/vmail/*/ 2>/dev/null || echo "0\t/var/mail/vmail/empty"'],
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False,
                _preload_content=True
            )

            # Parse du output and update per-domain storage
            domain_storage = self._parse_du_output(result, 'email')

            # Get total consumed space and mount size using df
            df_result = stream(
                self.core_v1.connect_get_namespaced_pod_exec,
                name=pod_name,
                namespace=namespace,
                command=['sh', '-c', "df -B1 /var/mail/vmail 2>/dev/null | tail -1 | awk '{print $2, $3}'"],
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False,
                _preload_content=True
            )

            # Parse df output: "total_size used_size"
            df_parts = df_result.strip().split()
            pvc_bytes = int(df_parts[0]) if len(df_parts) >= 1 and df_parts[0].isdigit() else 0
            total_bytes = int(df_parts[1]) if len(df_parts) >= 2 and df_parts[1].isdigit() else 0

            return {
                'component': 'smtp_storage',
                'status': 'healthy',
                'message': f'{self._format_bytes(total_bytes)} used of {self._format_bytes(pvc_bytes)}',
                'details': {
                    'total_bytes': total_bytes,
                    'pvc_bytes': pvc_bytes,
                    'domain_count': len(domain_storage),
                },
            }

        except ApiException as e:
            return {
                'component': 'smtp_storage',
                'status': 'error',
                'message': f'API error: {e.reason}',
                'details': {'status': e.status},
            }
        except Exception as e:
            return {
                'component': 'smtp_storage',
                'status': 'error',
                'message': f'Storage check failed: {e}',
                'details': {'error': str(e)},
            }

    def check_mariadb_storage(self):
        """
        Collect storage usage from MariaDB pod for all domains.

        Runs 'du -sb /var/lib/mysql/*' and parses per-database sizes.
        Database names use underscores instead of dots (e.g., zilda_hu for zilda.hu).
        Also collects PVC total size for summary.
        """
        namespace = 'kubepanel'
        label_selector = 'app=mariadb'

        try:
            pods = self.core_v1.list_namespaced_pod(
                namespace=namespace,
                label_selector=label_selector
            ).items

            running_pods = [p for p in pods if p.status.phase == 'Running']
            if not running_pods:
                return {
                    'component': 'mariadb_storage',
                    'status': 'error',
                    'message': 'MariaDB pod not running',
                    'details': {'namespace': namespace, 'selector': label_selector},
                }

            pod_name = running_pods[0].metadata.name

            # Get per-database storage usage
            result = stream(
                self.core_v1.connect_get_namespaced_pod_exec,
                name=pod_name,
                namespace=namespace,
                command=['sh', '-c', 'du -sb /var/lib/mysql/*/ 2>/dev/null || echo "0\t/var/lib/mysql/empty"'],
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False,
                _preload_content=True
            )

            # Parse du output and update per-domain storage
            domain_storage = self._parse_du_output(result, 'database')

            # Get total consumed space and mount size using df
            df_result = stream(
                self.core_v1.connect_get_namespaced_pod_exec,
                name=pod_name,
                namespace=namespace,
                command=['sh', '-c', "df -B1 /var/lib/mysql 2>/dev/null | tail -1 | awk '{print $2, $3}'"],
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False,
                _preload_content=True
            )

            # Parse df output: "total_size used_size"
            df_parts = df_result.strip().split()
            pvc_bytes = int(df_parts[0]) if len(df_parts) >= 1 and df_parts[0].isdigit() else 0
            total_bytes = int(df_parts[1]) if len(df_parts) >= 2 and df_parts[1].isdigit() else 0

            return {
                'component': 'mariadb_storage',
                'status': 'healthy',
                'message': f'{self._format_bytes(total_bytes)} used of {self._format_bytes(pvc_bytes)}',
                'details': {
                    'total_bytes': total_bytes,
                    'pvc_bytes': pvc_bytes,
                    'domain_count': len(domain_storage),
                },
            }

        except ApiException as e:
            return {
                'component': 'mariadb_storage',
                'status': 'error',
                'message': f'API error: {e.reason}',
                'details': {'status': e.status},
            }
        except Exception as e:
            return {
                'component': 'mariadb_storage',
                'status': 'error',
                'message': f'Storage check failed: {e}',
                'details': {'error': str(e)},
            }

    def _parse_du_output(self, output, storage_type):
        """
        Parse 'du -sb' output and update DomainStorageUsage records.

        Args:
            output: Output from du command (format: "SIZE\tPATH\n")
            storage_type: 'email' or 'database'

        Returns:
            dict: domain_name -> bytes
        """
        domain_storage = {}

        if not self.db_available:
            return domain_storage

        # Build domain lookup
        # For email: folder name is domain_name (e.g., zilda.hu)
        # For database: folder name is domain_name with dots replaced by underscores (e.g., zilda_hu)
        domains = {d.domain_name: d for d in Domain.objects.all()}

        if storage_type == 'database':
            # Also create underscore-to-domain lookup
            db_name_to_domain = {d.domain_name.replace('.', '_'): d for d in domains.values()}
        else:
            db_name_to_domain = {}

        now = timezone.now()

        for line in output.strip().split('\n'):
            if not line or '\t' not in line:
                continue

            parts = line.split('\t')
            if len(parts) != 2:
                continue

            try:
                size_bytes = int(parts[0])
            except ValueError:
                continue

            path = parts[1].rstrip('/')
            name = path.split('/')[-1]  # Get folder/db name

            # Skip system databases for MariaDB
            if storage_type == 'database' and name in ('mysql', 'sys', 'performance_schema', 'information_schema'):
                continue

            # Match to domain
            domain = None
            if storage_type == 'email':
                domain = domains.get(name)
            else:
                domain = db_name_to_domain.get(name)

            if not domain:
                if self.verbose:
                    self.stdout.write(f"  No domain match for {storage_type} folder: {name}")
                continue

            domain_storage[domain.domain_name] = size_bytes

            if self.verbose:
                self.stdout.write(f"  {domain.domain_name}: {self._format_bytes(size_bytes)} ({storage_type})")

            # Update DomainStorageUsage record
            try:
                usage, _ = DomainStorageUsage.objects.get_or_create(domain=domain)
                if storage_type == 'email':
                    usage.email_bytes = size_bytes
                    usage.email_checked_at = now
                else:
                    usage.database_bytes = size_bytes
                    usage.database_checked_at = now
                usage.save()
            except Exception as e:
                logger.error(f"Failed to update storage for {domain.domain_name}: {e}")

        return domain_storage

    @staticmethod
    def _format_bytes(size_bytes):
        """Format bytes to human-readable string."""
        if size_bytes == 0:
            return "0 B"

        units = ['B', 'KB', 'MB', 'GB', 'TB']
        unit_index = 0
        size = float(size_bytes)

        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1

        if unit_index == 0:
            return f"{int(size)} {units[unit_index]}"
        return f"{size:.1f} {units[unit_index]}"

    def sync_pvc_storage(self):
        """
        Sync PVC storage from DomainMetric to DomainStorageUsage.

        DomainMetric.storage_bytes is collected by collect_metrics command.
        This method copies the latest value to DomainStorageUsage.pvc_bytes
        so that total_bytes includes all storage types.
        """
        if not self.db_available:
            if self.verbose:
                self.stdout.write("[Sync PVC Storage] Database unavailable, skipping")
            return

        now = timezone.now()
        synced_count = 0

        for domain in Domain.objects.all():
            # Get latest DomainMetric for this domain
            latest_metric = DomainMetric.objects.filter(domain=domain).order_by('-timestamp').first()

            if not latest_metric or not latest_metric.storage_bytes:
                continue

            # Get or create DomainStorageUsage and update pvc_bytes
            usage, _ = DomainStorageUsage.objects.get_or_create(domain=domain)

            if usage.pvc_bytes != latest_metric.storage_bytes:
                usage.pvc_bytes = latest_metric.storage_bytes
                usage.pvc_checked_at = now
                usage.save()
                synced_count += 1

                if self.verbose:
                    self.stdout.write(
                        f"  {domain.domain_name}: synced pvc_bytes = {self._format_bytes(latest_metric.storage_bytes)}"
                    )

        if self.verbose and synced_count > 0:
            self.stdout.write(f"[Sync PVC Storage] Updated {synced_count} domains")

    def check_storage_notifications(self):
        """
        Check storage usage for all domains and send notifications if thresholds are exceeded.

        Storage data sources:
        - PVC/disk storage: Latest DomainMetric.storage_bytes (collected by collect_metrics)
        - Email storage: DomainStorageUsage.email_bytes (collected by collect_health)
        - Database storage: DomainStorageUsage.database_bytes (collected by collect_health)

        Notification levels:
        - INFO: storage >= info_threshold (default 85%)
        - WARNING: storage >= warning_threshold (default 90%)
        - ALERT: storage >= alert_threshold (default 95%)

        Respects notification frequency settings (e.g., INFO only once per month).
        """
        if not self.db_available:
            if self.verbose:
                self.stdout.write("[Storage Notifications] Database unavailable, skipping")
            return

        # Check if notifications are enabled
        if not getattr(self.system_settings, 'storage_notifications_enabled', True):
            if self.verbose:
                self.stdout.write("[Storage Notifications] Disabled in settings")
            return

        # Get thresholds and frequencies
        thresholds = {
            'alert': getattr(self.system_settings, 'storage_alert_threshold', 95),
            'warning': getattr(self.system_settings, 'storage_warning_threshold', 90),
            'info': getattr(self.system_settings, 'storage_info_threshold', 85),
        }
        frequencies = {
            'alert': timedelta(days=getattr(self.system_settings, 'storage_alert_frequency_days', 1)),
            'warning': timedelta(days=getattr(self.system_settings, 'storage_warning_frequency_days', 7)),
            'info': timedelta(days=getattr(self.system_settings, 'storage_info_frequency_days', 30)),
        }

        if self.verbose:
            self.stdout.write(f"[Storage Notifications] Thresholds: {thresholds}")
            self.stdout.write(f"[Storage Notifications] Frequencies: alert={frequencies['alert'].days}d, warning={frequencies['warning'].days}d, info={frequencies['info'].days}d")

        now = timezone.now()
        notifications_sent = 0

        # Iterate through all domains with storage usage data
        # (pvc_bytes is synced from DomainMetric by sync_pvc_storage())
        for usage in DomainStorageUsage.objects.select_related('domain', 'domain__owner').all():
            domain = usage.domain
            owner = domain.owner

            # Skip if owner has no email
            if not owner.email:
                if self.verbose:
                    self.stdout.write(f"  {domain.domain_name}: Owner has no email, skipping")
                continue

            # Get storage values from DomainStorageUsage (pvc_bytes synced from DomainMetric)
            pvc_bytes = usage.pvc_bytes
            email_bytes = usage.email_bytes
            database_bytes = usage.database_bytes

            # Calculate total storage usage
            storage_limit_bytes = domain.storage_size * 1024 * 1024 * 1024  # GB to bytes
            storage_used_bytes = usage.total_bytes  # pvc + email + database

            if storage_limit_bytes == 0:
                continue

            usage_percent = (storage_used_bytes / storage_limit_bytes) * 100

            if self.verbose:
                self.stdout.write(
                    f"  {domain.domain_name}: {usage_percent:.1f}% "
                    f"({self._format_bytes(storage_used_bytes)} / {self._format_bytes(storage_limit_bytes)}) "
                    f"[pvc={self._format_bytes(pvc_bytes)}, email={self._format_bytes(email_bytes)}, db={self._format_bytes(database_bytes)}]"
                )

            # Determine notification level (highest applicable)
            notification_level = None
            if usage_percent >= thresholds['alert']:
                notification_level = 'alert'
            elif usage_percent >= thresholds['warning']:
                notification_level = 'warning'
            elif usage_percent >= thresholds['info']:
                notification_level = 'info'

            if notification_level is None:
                continue

            # Check if notification was recently sent for this level
            last_notification = StorageNotificationLog.objects.filter(
                domain=domain,
                level=notification_level
            ).order_by('-sent_at').first()

            if last_notification:
                time_since_last = now - last_notification.sent_at
                if time_since_last < frequencies[notification_level]:
                    if self.verbose:
                        remaining = frequencies[notification_level] - time_since_last
                        self.stdout.write(
                            f"    -> {notification_level.upper()} notification sent recently, "
                            f"next in {remaining.days}d {remaining.seconds // 3600}h"
                        )
                    continue

            # Send notification
            if self.dry_run:
                self.stdout.write(
                    f"    -> [DRY RUN] Would send {notification_level.upper()} notification to {owner.email}"
                )
                continue

            if self._send_storage_notification(
                domain=domain,
                owner=owner,
                level=notification_level,
                usage_percent=usage_percent,
                storage_used_bytes=storage_used_bytes,
                storage_limit_bytes=storage_limit_bytes,
                pvc_bytes=pvc_bytes,
                email_bytes=email_bytes,
                database_bytes=database_bytes,
            ):
                # Log the notification
                StorageNotificationLog.objects.create(
                    domain=domain,
                    level=notification_level,
                    usage_percent=usage_percent,
                    storage_used_bytes=storage_used_bytes,
                    storage_limit_bytes=storage_limit_bytes,
                    recipient_email=owner.email,
                )
                notifications_sent += 1
                if self.verbose:
                    self.stdout.write(
                        f"    -> Sent {notification_level.upper()} notification to {owner.email}"
                    )

        if self.verbose or notifications_sent > 0:
            self.stdout.write(f"[Storage Notifications] Sent {notifications_sent} notifications")

    def _send_storage_notification(
        self,
        domain,
        owner,
        level: str,
        usage_percent: float,
        storage_used_bytes: int,
        storage_limit_bytes: int,
        pvc_bytes: int,
        email_bytes: int,
        database_bytes: int,
    ) -> bool:
        """
        Send a storage notification email to the domain owner.

        Returns True if email was sent successfully.
        """
        # Get email templates
        if level == 'alert':
            subject_template = self.system_settings.storage_alert_subject
            body_template = self.system_settings.storage_alert_template
        elif level == 'warning':
            subject_template = self.system_settings.storage_warning_subject
            body_template = self.system_settings.storage_warning_template
        else:
            subject_template = self.system_settings.storage_info_subject
            body_template = self.system_settings.storage_info_template

        # Prepare template variables
        template_vars = {
            'domain_name': domain.domain_name,
            'level': level.upper(),
            'usage_percent': f"{usage_percent:.1f}",
            'storage_used_gb': f"{storage_used_bytes / (1024**3):.2f}",
            'storage_limit_gb': f"{storage_limit_bytes / (1024**3):.2f}",
            'pvc_bytes': str(pvc_bytes),
            'email_bytes': str(email_bytes),
            'database_bytes': str(database_bytes),
            'pvc_gb': f"{pvc_bytes / (1024**3):.2f}",
            'email_gb': f"{email_bytes / (1024**3):.2f}",
            'database_gb': f"{database_bytes / (1024**3):.2f}",
        }

        # Render templates (simple {{var}} replacement)
        subject = subject_template
        body = body_template
        for var, value in template_vars.items():
            subject = subject.replace(f'{{{{{var}}}}}', value)
            body = body.replace(f'{{{{{var}}}}}', value)

        # Get sender email
        kubepanel_domain = settings.ALLOWED_HOSTS[0] if settings.ALLOWED_HOSTS else 'localhost'
        from_email = f'noreply@{kubepanel_domain}'
        from_name = 'KubePanel'
        formatted_from = f'{from_name} <{from_email}>'

        # Build email
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = formatted_from
        msg['To'] = owner.email

        try:
            # Send via internal SMTP
            with smtplib.SMTP('smtp-internal.kubepanel.svc.cluster.local', 25, timeout=30) as server:
                server.sendmail(from_email, [owner.email], msg.as_string())
            logger.info(f"Storage notification ({level}) sent to {owner.email} for {domain.domain_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to send storage notification to {owner.email}: {e}")
            if self.verbose:
                self.stdout.write(f"    -> Failed to send email: {e}")
            return False
