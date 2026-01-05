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

    def handle(self, *args, **options):
        self.dry_run = options.get('dry_run', False)
        specific_component = options.get('component')

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
        self.system_settings = SystemSettings.get_settings()

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
        Check Linstor volume integrity.

        Runs 'linstor volume list' in linstor-controller pod and parses the State column.
        Valid states: UpToDate, Diskless, TieBreaker
        """
        namespace = 'piraeus-datastore'
        label_selector = 'app.kubernetes.io/component=linstor-controller'

        try:
            pods = self.core_v1.list_namespaced_pod(
                namespace=namespace,
                label_selector=label_selector
            ).items

            if not pods:
                return {
                    'component': 'linstor',
                    'status': 'error',
                    'message': 'Linstor controller pod not found',
                    'details': {'namespace': namespace, 'selector': label_selector},
                }

            pod_name = pods[0].metadata.name

            # Execute linstor volume list
            result = stream(
                self.core_v1.connect_get_namespaced_pod_exec,
                name=pod_name,
                namespace=namespace,
                command=['linstor', 'volume', 'list'],
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False,
                _preload_content=True
            )

            return self.parse_linstor_output(result)

        except ApiException as e:
            return {
                'component': 'linstor',
                'status': 'error',
                'message': f'API error: {e.reason}',
                'details': {'status': e.status},
            }

    def parse_linstor_output(self, output):
        """Parse linstor volume list output and check State column."""
        valid_states = {'UpToDate', 'Diskless', 'TieBreaker'}
        error_states = []
        total_volumes = 0
        healthy_volumes = 0

        lines = output.strip().split('\n')
        for line in lines:
            # Skip header/border lines
            if '┊' not in line or 'Resource' in line or 'State' in line:
                continue

            # Parse table row - State is typically the 10th column
            parts = [p.strip() for p in line.split('┊') if p.strip()]
            if len(parts) >= 10:
                total_volumes += 1
                state = parts[9].strip() if len(parts) > 9 else ''

                if state in valid_states:
                    healthy_volumes += 1
                elif state:
                    error_states.append(f"{parts[0]}@{parts[1]}: {state}")

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

        Runs 'mariadb-admin ping' in mariadb pod.
        Output: "mysqld is alive" on success.
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
                    'component': 'mariadb',
                    'status': 'error',
                    'message': 'MariaDB pod not running',
                    'details': {'namespace': namespace, 'selector': label_selector},
                }

            pod_name = running_pods[0].metadata.name

            # Execute mariadb-admin ping
            result = stream(
                self.core_v1.connect_get_namespaced_pod_exec,
                name=pod_name,
                namespace=namespace,
                command=['mariadb-admin', 'ping'],
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False,
                _preload_content=True
            )

            if 'alive' in result.lower():
                return {
                    'component': 'mariadb',
                    'status': 'healthy',
                    'message': 'MariaDB is responding',
                    'details': {'response': result.strip()},
                }
            else:
                return {
                    'component': 'mariadb',
                    'status': 'error',
                    'message': f'Unexpected response: {result.strip()[:100]}',
                    'details': {'response': result.strip()},
                }

        except ApiException as e:
            return {
                'component': 'mariadb',
                'status': 'error',
                'message': f'API error: {e.reason}',
                'details': {'status': e.status},
            }

    def save_status(self, result):
        """Save health status to database."""
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

    def process_alerts(self, results):
        """Send email alerts for warning/error statuses."""
        if not self.system_settings.health_check_email_enabled:
            return

        # Collect components that need alerts
        alert_components = []
        for result in results:
            if result['status'] in ('warning', 'error'):
                # Check if alert already sent
                try:
                    status_obj = SystemHealthStatus.objects.get(component=result['component'])
                    if not status_obj.alert_sent:
                        alert_components.append(result)
                        status_obj.alert_sent = True
                        status_obj.save()
                except SystemHealthStatus.DoesNotExist:
                    pass

        if not alert_components:
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

        # Get superuser emails
        superusers = User.objects.filter(is_superuser=True, is_active=True)
        recipient_emails = [u.email for u in superusers if u.email]

        if not recipient_emails:
            logger.warning('No superuser emails configured for health alerts')
            return

        try:
            send_mail(
                subject=subject,
                message=body,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=recipient_emails,
                fail_silently=False,
            )
            logger.info(f'Health alert sent to {len(recipient_emails)} recipients')
        except Exception as e:
            logger.error(f'Failed to send health alert email: {e}')
