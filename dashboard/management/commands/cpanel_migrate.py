"""
cPanel Migration CLI Tool

A command-line interface for bulk migration from cPanel servers to KubePanel.
Designed for hosting providers who prefer scripting migrations.

Usage:
    python manage.py cpanel_migrate connect --host cpanel.example.com --user admin --token XXX
    python manage.py cpanel_migrate discover --host cpanel.example.com --user admin --token XXX
    python manage.py cpanel_migrate migrate --host cpanel.example.com --user admin --token XXX --owner john
    python manage.py cpanel_migrate status --batch-id 42
    python manage.py cpanel_migrate list

Examples:
    # Test connection to cPanel server
    python manage.py cpanel_migrate connect -H cpanel.example.com -u admin -t "API_TOKEN"

    # Discover domains on a cPanel server
    python manage.py cpanel_migrate discover -H cpanel.example.com -u admin -t "API_TOKEN" --json

    # Migrate all domains to a specific owner
    python manage.py cpanel_migrate migrate -H cpanel.example.com -u admin -t "API_TOKEN" \\
        --owner john --package "Basic"

    # Migrate specific domains only
    python manage.py cpanel_migrate migrate -H cpanel.example.com -u admin -t "API_TOKEN" \\
        --owner john --domains example.com,shop.example.com

    # Interactive mode (prompts for domain selection)
    python manage.py cpanel_migrate migrate -H cpanel.example.com -u admin -t "API_TOKEN" \\
        --owner john --interactive

    # Check migration status
    python manage.py cpanel_migrate status --batch-id 42

    # List all migration batches
    python manage.py cpanel_migrate list
"""

import json
import sys
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User

from dashboard.models import MigrationBatch, MigrationDomain, Package
from dashboard.services.cpanel_api import (
    CPanelClient,
    CPanelAPIError,
    CPanelConnectionError,
    serialize_domain_info,
)


class Command(BaseCommand):
    help = 'cPanel to KubePanel migration CLI tool'

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(dest='subcommand', help='Available commands')

        # Connect command
        connect_parser = subparsers.add_parser('connect', help='Test connection to cPanel server')
        self._add_connection_args(connect_parser)

        # Discover command
        discover_parser = subparsers.add_parser('discover', help='Discover domains on cPanel server')
        self._add_connection_args(discover_parser)
        discover_parser.add_argument(
            '--json',
            action='store_true',
            help='Output in JSON format'
        )

        # Migrate command
        migrate_parser = subparsers.add_parser('migrate', help='Migrate domains from cPanel')
        self._add_connection_args(migrate_parser)
        migrate_parser.add_argument(
            '--owner', '-o',
            required=True,
            help='KubePanel username to own migrated domains'
        )
        migrate_parser.add_argument(
            '--package', '-p',
            help='Package name to assign to migrated domains'
        )
        migrate_parser.add_argument(
            '--domains', '-d',
            help='Comma-separated list of specific domains to migrate (default: all)'
        )
        migrate_parser.add_argument(
            '--interactive', '-i',
            action='store_true',
            help='Interactive mode - prompt for domain selection'
        )
        migrate_parser.add_argument(
            '--skip-email',
            action='store_true',
            help='Skip email/mailbox migration'
        )
        migrate_parser.add_argument(
            '--skip-database',
            action='store_true',
            help='Skip database migration'
        )
        migrate_parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be migrated without actually doing it'
        )
        migrate_parser.add_argument(
            '--background',
            action='store_true',
            help='Run migration in background (creates K8s Job)'
        )

        # Status command
        status_parser = subparsers.add_parser('status', help='Check migration status')
        status_parser.add_argument(
            '--batch-id', '-b',
            type=int,
            help='Migration batch ID to check'
        )
        status_parser.add_argument(
            '--watch', '-w',
            action='store_true',
            help='Continuously watch status (refresh every 5 seconds)'
        )
        status_parser.add_argument(
            '--json',
            action='store_true',
            help='Output in JSON format'
        )

        # List command
        list_parser = subparsers.add_parser('list', help='List migration batches')
        list_parser.add_argument(
            '--status', '-s',
            choices=['configuring', 'pending', 'running', 'completed', 'failed', 'cancelled'],
            help='Filter by status'
        )
        list_parser.add_argument(
            '--json',
            action='store_true',
            help='Output in JSON format'
        )

        # Cancel command
        cancel_parser = subparsers.add_parser('cancel', help='Cancel a running migration')
        cancel_parser.add_argument(
            '--batch-id', '-b',
            type=int,
            required=True,
            help='Migration batch ID to cancel'
        )

    def _add_connection_args(self, parser):
        """Add common cPanel connection arguments to a parser."""
        parser.add_argument(
            '--host', '-H',
            required=True,
            help='cPanel server hostname or IP'
        )
        parser.add_argument(
            '--port', '-P',
            type=int,
            default=2087,
            help='WHM port (default: 2087)'
        )
        parser.add_argument(
            '--user', '-u',
            required=True,
            help='cPanel username'
        )
        parser.add_argument(
            '--token', '-t',
            required=True,
            help='cPanel API token'
        )
        parser.add_argument(
            '--no-verify-ssl',
            action='store_true',
            help='Disable SSL certificate verification'
        )

    def handle(self, *args, **options):
        subcommand = options.get('subcommand')

        if not subcommand:
            self.print_help('manage.py', 'cpanel_migrate')
            return

        if subcommand == 'connect':
            self.handle_connect(options)
        elif subcommand == 'discover':
            self.handle_discover(options)
        elif subcommand == 'migrate':
            self.handle_migrate(options)
        elif subcommand == 'status':
            self.handle_status(options)
        elif subcommand == 'list':
            self.handle_list(options)
        elif subcommand == 'cancel':
            self.handle_cancel(options)
        else:
            raise CommandError(f"Unknown subcommand: {subcommand}")

    def _get_client(self, options) -> CPanelClient:
        """Create a CPanelClient from command options."""
        return CPanelClient(
            hostname=options['host'],
            port=options['port'],
            username=options['user'],
            api_token=options['token'],
            verify_ssl=not options.get('no_verify_ssl', False),
        )

    def handle_connect(self, options):
        """Test connection to cPanel server."""
        self.stdout.write(f"Connecting to {options['host']}:{options['port']}...")

        try:
            client = self._get_client(options)
            client.test_connection()
            self.stdout.write(self.style.SUCCESS("Connection successful!"))

            # Show some basic info
            domains = client.list_domains()
            self.stdout.write(f"  Found {len(domains)} domain(s)")
            for domain in domains[:5]:
                self.stdout.write(f"    - {domain.name} ({domain.type})")
            if len(domains) > 5:
                self.stdout.write(f"    ... and {len(domains) - 5} more")

        except CPanelConnectionError as e:
            raise CommandError(f"Connection failed: {e}")
        except CPanelAPIError as e:
            raise CommandError(f"API error: {e}")

    def handle_discover(self, options):
        """Discover domains, databases, and mailboxes on cPanel server."""
        self.stdout.write(f"Discovering domains on {options['host']}...")

        try:
            client = self._get_client(options)
            domains = client.list_domains()

            if options.get('json'):
                # JSON output
                output = {
                    'server': options['host'],
                    'username': options['user'],
                    'domains': [serialize_domain_info(d) for d in domains]
                }
                self.stdout.write(json.dumps(output, indent=2))
            else:
                # Human-readable output
                self.stdout.write(self.style.SUCCESS(f"\nFound {len(domains)} domain(s):\n"))

                for domain in domains:
                    self.stdout.write(f"  {self.style.MIGRATE_HEADING(domain.name)} ({domain.type})")

                    if domain.databases:
                        self.stdout.write(f"    Databases ({len(domain.databases)}):")
                        for db in domain.databases:
                            self.stdout.write(f"      - {db.name} ({db.size_mb:.1f} MB)")

                    if domain.mailboxes:
                        self.stdout.write(f"    Mailboxes ({len(domain.mailboxes)}):")
                        for mb in domain.mailboxes:
                            self.stdout.write(f"      - {mb.email} ({mb.size_mb:.1f} MB)")

                    self.stdout.write("")

        except CPanelConnectionError as e:
            raise CommandError(f"Connection failed: {e}")
        except CPanelAPIError as e:
            raise CommandError(f"API error: {e}")

    def handle_migrate(self, options):
        """Migrate domains from cPanel to KubePanel."""
        # Validate owner
        try:
            owner = User.objects.get(username=options['owner'])
        except User.DoesNotExist:
            raise CommandError(f"User '{options['owner']}' not found")

        # Validate package if specified
        package = None
        if options.get('package'):
            try:
                package = Package.objects.get(name=options['package'])
            except Package.DoesNotExist:
                raise CommandError(f"Package '{options['package']}' not found")

        self.stdout.write(f"Connecting to {options['host']}...")

        try:
            client = self._get_client(options)
            domains = client.list_domains()
        except CPanelConnectionError as e:
            raise CommandError(f"Connection failed: {e}")
        except CPanelAPIError as e:
            raise CommandError(f"API error: {e}")

        # Filter domains if specified
        if options.get('domains'):
            domain_filter = [d.strip() for d in options['domains'].split(',')]
            domains = [d for d in domains if d.name in domain_filter]
            if not domains:
                raise CommandError("None of the specified domains were found")

        # Interactive mode
        if options.get('interactive'):
            domains = self._interactive_select(domains)
            if not domains:
                self.stdout.write("No domains selected. Exiting.")
                return

        if not domains:
            raise CommandError("No domains to migrate")

        # Show migration plan
        self.stdout.write(self.style.MIGRATE_HEADING("\nMigration Plan:"))
        self.stdout.write(f"  Source: {options['host']}")
        self.stdout.write(f"  Owner: {owner.username}")
        self.stdout.write(f"  Package: {package.name if package else 'Default'}")
        self.stdout.write(f"  Domains: {len(domains)}")
        self.stdout.write(f"  Skip Email: {options.get('skip_email', False)}")
        self.stdout.write(f"  Skip Database: {options.get('skip_database', False)}")
        self.stdout.write("")

        for domain in domains:
            db_info = f", DB: {domain.databases[0].name}" if domain.databases and not options.get('skip_database') else ""
            mail_info = f", {len(domain.mailboxes)} mailbox(es)" if domain.mailboxes and not options.get('skip_email') else ""
            self.stdout.write(f"    - {domain.name}{db_info}{mail_info}")

        # Dry run?
        if options.get('dry_run'):
            self.stdout.write(self.style.WARNING("\n[DRY RUN] No changes made."))
            return

        # Confirm
        self.stdout.write("")
        confirm = input("Proceed with migration? [y/N] ")
        if confirm.lower() != 'y':
            self.stdout.write("Migration cancelled.")
            return

        # Create migration batch
        self.stdout.write("\nCreating migration batch...")

        batch = MigrationBatch.objects.create(
            cpanel_hostname=options['host'],
            cpanel_port=options['port'],
            cpanel_username=options['user'],
            created_by=owner,
            status='configuring',
            discovered_domains=[serialize_domain_info(d) for d in domains],
        )
        batch.set_api_token(options['token'])
        batch.save()

        # Create migration domains
        for domain in domains:
            # Select first database by default (unless skipped)
            selected_db = ''
            if domain.databases and not options.get('skip_database'):
                selected_db = domain.databases[0].name

            # Select all mailboxes by default (unless skipped)
            selected_mailboxes = []
            if domain.mailboxes and not options.get('skip_email'):
                selected_mailboxes = [mb.email for mb in domain.mailboxes]

            MigrationDomain.objects.create(
                batch=batch,
                source_domain=domain.name,
                source_username=domain.user or options['user'],
                target_owner=owner,
                target_package=package,
                available_databases=[{'name': db.name, 'size_mb': db.size_mb} for db in domain.databases],
                selected_database=selected_db,
                available_mailboxes=[{'email': mb.email, 'size_mb': mb.size_mb} for mb in domain.mailboxes],
                selected_mailboxes=selected_mailboxes,
                email_method='backup' if selected_mailboxes else 'none',
            )

        self.stdout.write(self.style.SUCCESS(f"Created migration batch #{batch.id}"))

        if options.get('background'):
            # Start as K8s Job
            from dashboard.services.migration_job import create_migration_job
            from django.utils import timezone

            batch.status = 'pending'
            batch.save()

            try:
                job_name = create_migration_job(batch.id)
                batch.job_name = job_name
                batch.status = 'running'
                batch.started_at = timezone.now()
                batch.save()

                self.stdout.write(self.style.SUCCESS(f"Migration job started: {job_name}"))
                self.stdout.write(f"Check status with: python manage.py cpanel_migrate status -b {batch.id}")
            except Exception as e:
                batch.status = 'failed'
                batch.save()
                raise CommandError(f"Failed to start migration job: {e}")
        else:
            # Run in foreground
            self._run_migration_foreground(batch, client)

    def _interactive_select(self, domains):
        """Interactive domain selection."""
        self.stdout.write("\nAvailable domains:")
        for i, domain in enumerate(domains, 1):
            db_count = len(domain.databases)
            mail_count = len(domain.mailboxes)
            self.stdout.write(f"  [{i}] {domain.name} ({db_count} DB, {mail_count} mailboxes)")

        self.stdout.write("")
        self.stdout.write("Enter domain numbers to migrate (comma-separated), 'all', or 'q' to quit:")
        selection = input("> ").strip()

        if selection.lower() == 'q':
            return []
        if selection.lower() == 'all':
            return domains

        try:
            indices = [int(x.strip()) - 1 for x in selection.split(',')]
            return [domains[i] for i in indices if 0 <= i < len(domains)]
        except (ValueError, IndexError):
            self.stderr.write("Invalid selection")
            return []

    def _run_migration_foreground(self, batch, client):
        """Run migration in foreground with progress output."""
        from django.utils import timezone
        from dashboard.services.cpanel_parser import CPanelBackupParser, CPanelParserError
        from dashboard.services.cpanel_transformer import CPanelTransformer
        import tempfile
        import os
        import shutil

        batch.status = 'running'
        batch.started_at = timezone.now()
        batch.save()

        work_dir = tempfile.mkdtemp(prefix='migration_cli_')
        self.stdout.write(f"Work directory: {work_dir}")

        try:
            # Download backup
            self.stdout.write("\nDownloading backup from cPanel...")
            backup_path = os.path.join(work_dir, 'backup.tar.gz')

            def progress_callback(stage, message, percent):
                if percent:
                    bar = '=' * (percent // 5) + ' ' * (20 - percent // 5)
                    self.stdout.write(f"\r  [{bar}] {percent}% - {message}", ending='')
                    self.stdout.flush()

            try:
                client.trigger_and_download_backup(
                    dest_path=backup_path,
                    progress_callback=progress_callback,
                    timeout=3600,
                )
                self.stdout.write("")  # New line after progress
                self.stdout.write(self.style.SUCCESS("  Backup downloaded successfully"))
            except TimeoutError:
                raise CommandError("Backup download timed out")

            # Process each domain
            for md in batch.domains.all():
                self.stdout.write(f"\nProcessing {md.source_domain}...")

                try:
                    md.status = 'fetching'
                    md.started_at = timezone.now()
                    md.save()

                    with CPanelBackupParser(backup_path) as parser:
                        transformer = CPanelTransformer()
                        domain_work_dir = os.path.join(work_dir, md.source_domain.replace('.', '-'))
                        os.makedirs(domain_work_dir, exist_ok=True)

                        # Extract files
                        self.stdout.write("  Extracting website files...")
                        public_html_path = os.path.join(domain_work_dir, 'html')
                        try:
                            parser.extract_public_html(public_html_path)
                        except CPanelParserError:
                            public_html_path = None

                        # Extract database
                        database_sql_path = None
                        if md.selected_database:
                            self.stdout.write(f"  Extracting database {md.selected_database}...")
                            database_sql_path = os.path.join(domain_work_dir, 'database.sql')
                            try:
                                parser.extract_database(md.selected_database, database_sql_path)
                            except CPanelParserError:
                                database_sql_path = None

                        # Create domain in KubePanel
                        self.stdout.write("  Creating domain in KubePanel...")
                        md.status = 'creating'
                        md.progress_percent = 30
                        md.save()

                        from dashboard.models import Domain, WorkloadVersion

                        default_workload = WorkloadVersion.objects.filter(
                            workload_type__slug='php',
                            is_default=True,
                            is_active=True
                        ).first() or WorkloadVersion.objects.filter(is_active=True).first()

                        if md.target_package:
                            storage = md.target_package.max_storage_size
                            cpu = md.target_package.max_cpu
                            mem = md.target_package.max_memory
                        else:
                            storage, cpu, mem = 10, 500, 512

                        domain_obj = Domain.objects.create(
                            domain_name=md.source_domain,
                            title=f"Migrated from cPanel",
                            owner=md.target_owner,
                            storage_size=storage,
                            cpu_limit=cpu,
                            mem_limit=mem,
                            workload_version=default_workload,
                            email_enabled=bool(md.selected_mailboxes),
                        )

                        md.target_domain = domain_obj
                        md.save()

                        # Create Domain CR
                        from dashboard.k8s import create_domain, DomainSpec

                        spec = DomainSpec(
                            domain_name=md.source_domain,
                            storage_size=storage,
                            cpu_limit=cpu,
                            mem_limit=mem,
                            workload_type=default_workload.workload_type.slug,
                            workload_version=default_workload.version,
                            workload_image=default_workload.image_url,
                            workload_port=default_workload.workload_type.app_port,
                            proxy_mode=default_workload.workload_type.proxy_mode,
                            email_enabled=bool(md.selected_mailboxes),
                        )
                        create_domain(spec)

                        self.stdout.write("  Waiting for domain to be ready...")
                        # TODO: Wait for domain ready

                        # Import files/database
                        if public_html_path or database_sql_path:
                            self.stdout.write("  Importing files and database...")
                            md.status = 'importing_files'
                            md.progress_percent = 50
                            md.save()

                            archive_path = os.path.join(domain_work_dir, 'restore.tar.gz')
                            transformer.create_restore_archive(
                                public_html_path=public_html_path,
                                database_sql_path=database_sql_path,
                                output_path=archive_path,
                            )

                            # TODO: Upload and restore
                            self.stdout.write(self.style.WARNING("    [Skipped] Restore requires K8s access"))

                        # Import mailboxes
                        if md.selected_mailboxes:
                            self.stdout.write(f"  Importing {len(md.selected_mailboxes)} mailbox(es)...")
                            md.status = 'importing_mail'
                            md.progress_percent = 80
                            md.save()
                            # TODO: Import mailboxes
                            self.stdout.write(self.style.WARNING("    [Skipped] Mailbox import requires K8s access"))

                        md.status = 'completed'
                        md.progress_percent = 100
                        md.completed_at = timezone.now()
                        md.save()
                        self.stdout.write(self.style.SUCCESS(f"  {md.source_domain} completed"))

                except Exception as e:
                    md.status = 'failed'
                    md.error_message = str(e)
                    md.save()
                    self.stderr.write(self.style.ERROR(f"  {md.source_domain} failed: {e}"))

            # Update batch status
            completed = batch.domains.filter(status='completed').count()
            failed = batch.domains.filter(status='failed').count()
            total = batch.domains.count()

            batch.status = 'completed' if failed == 0 else 'failed' if completed == 0 else 'completed'
            batch.completed_at = timezone.now()
            batch.save()

            self.stdout.write("")
            self.stdout.write(self.style.SUCCESS(f"Migration complete: {completed}/{total} succeeded, {failed} failed"))

        finally:
            shutil.rmtree(work_dir, ignore_errors=True)
            batch.clear_api_token()

    def handle_status(self, options):
        """Check migration status."""
        batch_id = options.get('batch_id')

        if not batch_id:
            # Show latest batch
            batch = MigrationBatch.objects.order_by('-created_at').first()
            if not batch:
                raise CommandError("No migration batches found")
        else:
            try:
                batch = MigrationBatch.objects.get(id=batch_id)
            except MigrationBatch.DoesNotExist:
                raise CommandError(f"Migration batch #{batch_id} not found")

        if options.get('watch'):
            self._watch_status(batch, options.get('json'))
        else:
            self._show_status(batch, options.get('json'))

    def _show_status(self, batch, as_json=False):
        """Show status of a migration batch."""
        if as_json:
            output = {
                'id': batch.id,
                'status': batch.status,
                'source': batch.cpanel_hostname,
                'total_domains': batch.total_domains,
                'completed_domains': batch.completed_domains,
                'failed_domains': batch.failed_domains,
                'progress_percent': batch.progress_percent,
                'created_at': batch.created_at.isoformat(),
                'started_at': batch.started_at.isoformat() if batch.started_at else None,
                'completed_at': batch.completed_at.isoformat() if batch.completed_at else None,
                'domains': [
                    {
                        'name': d.source_domain,
                        'status': d.status,
                        'progress': d.progress_percent,
                        'message': d.progress_message,
                        'error': d.error_message,
                    }
                    for d in batch.domains.all()
                ]
            }
            self.stdout.write(json.dumps(output, indent=2))
        else:
            # Status badge
            status_styles = {
                'configuring': self.style.WARNING,
                'pending': self.style.WARNING,
                'running': self.style.NOTICE,
                'completed': self.style.SUCCESS,
                'failed': self.style.ERROR,
                'cancelled': self.style.WARNING,
            }
            style = status_styles.get(batch.status, lambda x: x)

            self.stdout.write(f"\nMigration Batch #{batch.id}")
            self.stdout.write(f"  Status: {style(batch.status.upper())}")
            self.stdout.write(f"  Source: {batch.cpanel_hostname}")
            self.stdout.write(f"  Progress: {batch.completed_domains}/{batch.total_domains} domains ({batch.progress_percent}%)")

            if batch.backup_status:
                self.stdout.write(f"  Backup: {batch.backup_status} ({batch.backup_progress}%)")

            self.stdout.write(f"\nDomains:")
            for d in batch.domains.all():
                if d.status == 'completed':
                    icon = self.style.SUCCESS('OK')
                elif d.status == 'failed':
                    icon = self.style.ERROR('FAIL')
                elif d.status in ['queued', 'skipped']:
                    icon = '  '
                else:
                    icon = self.style.WARNING('...')

                self.stdout.write(f"  [{icon}] {d.source_domain} - {d.get_status_display()} ({d.progress_percent}%)")
                if d.error_message:
                    self.stdout.write(f"       Error: {d.error_message}")

    def _watch_status(self, batch, as_json=False):
        """Continuously watch migration status."""
        import time

        try:
            while batch.status in ['configuring', 'pending', 'running']:
                # Clear screen
                self.stdout.write('\033[2J\033[H', ending='')
                self._show_status(batch, as_json)
                self.stdout.write(f"\n[Watching... Press Ctrl+C to stop]")
                time.sleep(5)
                batch.refresh_from_db()

            # Show final status
            self.stdout.write('\033[2J\033[H', ending='')
            self._show_status(batch, as_json)

        except KeyboardInterrupt:
            self.stdout.write("\nStopped watching.")

    def handle_list(self, options):
        """List migration batches."""
        batches = MigrationBatch.objects.all().order_by('-created_at')

        if options.get('status'):
            batches = batches.filter(status=options['status'])

        if options.get('json'):
            output = [
                {
                    'id': b.id,
                    'status': b.status,
                    'source': b.cpanel_hostname,
                    'total_domains': b.total_domains,
                    'completed': b.completed_domains,
                    'failed': b.failed_domains,
                    'created_at': b.created_at.isoformat(),
                }
                for b in batches
            ]
            self.stdout.write(json.dumps(output, indent=2))
        else:
            if not batches:
                self.stdout.write("No migration batches found.")
                return

            self.stdout.write(f"\n{'ID':<6} {'Status':<12} {'Source':<30} {'Domains':<15} {'Created':<20}")
            self.stdout.write("-" * 90)

            for b in batches:
                domains_str = f"{b.completed_domains}/{b.total_domains}"
                if b.failed_domains:
                    domains_str += f" ({b.failed_domains} failed)"

                self.stdout.write(
                    f"{b.id:<6} {b.status:<12} {b.cpanel_hostname[:28]:<30} "
                    f"{domains_str:<15} {b.created_at.strftime('%Y-%m-%d %H:%M'):<20}"
                )

    def handle_cancel(self, options):
        """Cancel a running migration."""
        batch_id = options['batch_id']

        try:
            batch = MigrationBatch.objects.get(id=batch_id)
        except MigrationBatch.DoesNotExist:
            raise CommandError(f"Migration batch #{batch_id} not found")

        if batch.status not in ['pending', 'running']:
            raise CommandError(f"Cannot cancel migration in '{batch.status}' status")

        # Delete K8s job if exists
        if batch.job_name:
            from dashboard.services.migration_job import delete_migration_job
            try:
                delete_migration_job(batch.job_name)
                self.stdout.write(f"Deleted migration job: {batch.job_name}")
            except Exception as e:
                self.stderr.write(f"Warning: Could not delete job: {e}")

        batch.status = 'cancelled'
        from django.utils import timezone
        batch.completed_at = timezone.now()
        batch.save()

        batch.domains.filter(status='queued').update(status='skipped')
        batch.clear_api_token()

        self.stdout.write(self.style.SUCCESS(f"Migration batch #{batch_id} cancelled"))
