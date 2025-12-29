"""
Django management command to migrate DNS from Domain CRs to DNSZone CRs.

This command migrates existing domains that have dns.enabled in their spec
to use the new separate DNSZone CR.

Usage:
    python manage.py migrate_dns_to_dnszone [--dry-run]
"""

from django.core.management.base import BaseCommand
import logging

from dashboard.k8s import (
    list_domains,
    get_domain,
    K8sClientError,
    K8sNotFoundError,
)
from dashboard.k8s.dnszone import (
    create_dnszone,
    dnszone_exists,
)

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Migrate DNS from Domain CRs to DNSZone CRs'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without making changes',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']

        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN MODE - No changes will be made'))

        try:
            domains = list_domains()
        except K8sClientError as e:
            self.stderr.write(self.style.ERROR(f'Failed to list domains: {e}'))
            return

        self.stdout.write(f'Found {len(domains)} domains')

        migrated = 0
        skipped = 0
        errors = 0

        for domain in domains:
            domain_name = domain.domain_name
            dns_spec = domain.spec.get('dns', {})
            dns_enabled = dns_spec.get('enabled', False)

            if not dns_enabled:
                self.stdout.write(f'  {domain_name}: DNS not enabled, skipping')
                skipped += 1
                continue

            # Check if DNSZone already exists
            if dnszone_exists(domain_name):
                self.stdout.write(f'  {domain_name}: DNSZone already exists, skipping')
                skipped += 1
                continue

            # Get credential secret ref
            credential_ref = dns_spec.get('credentialSecretRef')
            if not credential_ref:
                self.stderr.write(
                    self.style.WARNING(f'  {domain_name}: No credentialSecretRef, skipping')
                )
                skipped += 1
                continue

            # Get records from status (they have recordIds)
            status_raw = domain.status._raw if domain.status else {}
            dns_status = status_raw.get('dns', {})
            status_records = dns_status.get('records', [])

            # Also get records from spec (in case some don't have recordIds yet)
            spec_records = dns_spec.get('records', [])

            # Build records for DNSZone CR
            # Prefer status records (they have recordIds), but merge with spec records
            records = []
            status_record_ids = set()

            for sr in status_records:
                record = {
                    'type': sr.get('type'),
                    'name': sr.get('name'),
                    'content': sr.get('content'),
                    'ttl': sr.get('ttl', 1),
                    'proxied': sr.get('proxied', False),
                }
                if sr.get('priority') is not None:
                    record['priority'] = sr.get('priority')
                if sr.get('recordId'):
                    record['recordId'] = sr.get('recordId')
                    status_record_ids.add(sr.get('recordId'))
                records.append(record)

            # Add spec records that don't have recordIds in status
            for spec_rec in spec_records:
                # Check if this record is already in status by (type, name, content)
                already_added = False
                for sr in status_records:
                    if (sr.get('type') == spec_rec.get('type') and
                        sr.get('name') == spec_rec.get('name') and
                        sr.get('content') == spec_rec.get('content')):
                        already_added = True
                        break
                if not already_added:
                    record = {
                        'type': spec_rec.get('type'),
                        'name': spec_rec.get('name'),
                        'content': spec_rec.get('content'),
                        'ttl': spec_rec.get('ttl', 1),
                        'proxied': spec_rec.get('proxied', False),
                    }
                    if spec_rec.get('priority') is not None:
                        record['priority'] = spec_rec.get('priority')
                    # No recordId since it's not synced yet
                    records.append(record)

            self.stdout.write(
                f'  {domain_name}: Migrating {len(records)} DNS records'
            )

            if dry_run:
                migrated += 1
                continue

            try:
                create_dnszone(
                    zone_name=domain_name,
                    credential_secret_ref=credential_ref,
                    records=records,
                )
                self.stdout.write(
                    self.style.SUCCESS(f'  {domain_name}: DNSZone CR created successfully')
                )
                migrated += 1
            except K8sClientError as e:
                self.stderr.write(
                    self.style.ERROR(f'  {domain_name}: Failed to create DNSZone CR: {e}')
                )
                errors += 1

        self.stdout.write('')
        self.stdout.write('Migration summary:')
        self.stdout.write(f'  Migrated: {migrated}')
        self.stdout.write(f'  Skipped: {skipped}')
        self.stdout.write(f'  Errors: {errors}')

        if dry_run:
            self.stdout.write('')
            self.stdout.write(
                self.style.WARNING('This was a dry run. Run without --dry-run to apply changes.')
            )
