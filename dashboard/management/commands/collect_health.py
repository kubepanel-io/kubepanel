"""
Collect system health status from Kubernetes cluster components.

Run this command every 5 minutes via a sidecar container:
    while true; do python manage.py collect_health; sleep 300; done

Components checked:
- Linstor: Volume integrity via 'linstor volume list'
- Mail Queue: Postfix queue size via 'postqueue -p'
- MariaDB: Database health via 'mysqladmin ping'
"""
import os
import re
import logging
from django.core.management.base import BaseCommand
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.models import User

from kubernetes import client, config
from kubernetes.stream import stream
from kubernetes.client.rest import ApiException

from dashboard.models import SystemHealthStatus, SystemSettings

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
            choices=['linstor', 'mail_queue', 'mariadb'],
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

        # Components to check
        components = ['linstor', 'mail_queue', 'mariadb']
        if specific_component:
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

        # Send alerts if needed
        if not self.dry_run:
            self.process_alerts(results)

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

        try:
            if self.verbose:
                self.stdout.write(f"[Alerts] Sending email to: {recipient_emails}")
            send_mail(
                subject=subject,
                message=body,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=recipient_emails,
                fail_silently=False,
            )
            logger.info(f'Health alert sent to {len(recipient_emails)} recipients')
            if self.verbose:
                self.stdout.write(f"[Alerts] Email sent successfully to {len(recipient_emails)} recipients")
        except Exception as e:
            logger.error(f'Failed to send health alert email: {e}')
            if self.verbose:
                self.stdout.write(f"[Alerts] Failed to send email: {e}")
