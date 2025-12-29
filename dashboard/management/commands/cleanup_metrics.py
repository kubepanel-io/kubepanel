"""
Clean up old metrics data and aggregate into hourly/daily summaries.

Run this command once per hour via a Kubernetes CronJob:
    python manage.py cleanup_metrics

Retention policy:
- 5-minute data: 24 hours
- Hourly data: 7 days
- Daily data: 30 days
"""
import logging
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db.models import Avg, Sum, Count

from dashboard.models import Domain, DomainMetric

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Clean up old metrics and aggregate into hourly/daily summaries'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting',
        )
        parser.add_argument(
            '--aggregate-only',
            action='store_true',
            help='Only create aggregates, do not delete old data',
        )
        parser.add_argument(
            '--cleanup-only',
            action='store_true',
            help='Only delete old data, do not create aggregates',
        )

    def handle(self, *args, **options):
        self.dry_run = options.get('dry_run', False)
        aggregate_only = options.get('aggregate_only', False)
        cleanup_only = options.get('cleanup_only', False)

        now = timezone.now()

        # 1. Aggregate 5-minute data into hourly (for data older than 1 hour)
        if not cleanup_only:
            self.aggregate_to_hourly(now)

        # 2. Aggregate hourly data into daily (for data older than 1 day)
        if not cleanup_only:
            self.aggregate_to_daily(now)

        # 3. Delete old data according to retention policy
        if not aggregate_only:
            self.cleanup_old_data(now)

    def aggregate_to_hourly(self, now):
        """Aggregate 5-minute data into hourly summaries."""
        # Find hours that need aggregation (data older than 1 hour, not yet aggregated)
        cutoff = now - timedelta(hours=1)

        for domain in Domain.objects.all():
            # Get 5-minute data that needs aggregation
            old_data = DomainMetric.objects.filter(
                domain=domain,
                period='5min',
                timestamp__lt=cutoff
            ).order_by('timestamp')

            if not old_data.exists():
                continue

            # Group by hour
            hours_processed = set()
            for metric in old_data:
                hour_start = metric.timestamp.replace(minute=0, second=0, microsecond=0)

                if hour_start in hours_processed:
                    continue

                # Check if hourly aggregate already exists
                if DomainMetric.objects.filter(
                    domain=domain,
                    period='hourly',
                    timestamp=hour_start
                ).exists():
                    hours_processed.add(hour_start)
                    continue

                # Get all 5-minute data for this hour
                hour_end = hour_start + timedelta(hours=1)
                hour_data = DomainMetric.objects.filter(
                    domain=domain,
                    period='5min',
                    timestamp__gte=hour_start,
                    timestamp__lt=hour_end
                )

                if hour_data.exists():
                    aggregates = hour_data.aggregate(
                        avg_cpu=Avg('cpu_millicores'),
                        avg_memory=Avg('memory_bytes'),
                        sum_requests=Sum('http_requests'),
                        sum_2xx=Sum('http_2xx'),
                        sum_3xx=Sum('http_3xx'),
                        sum_4xx=Sum('http_4xx'),
                        sum_5xx=Sum('http_5xx'),
                        avg_latency=Avg('avg_latency_ms'),
                        sum_bytes_in=Sum('bytes_in'),
                        sum_bytes_out=Sum('bytes_out'),
                    )

                    # Get limit values from any record (they should be the same)
                    sample = hour_data.first()

                    if not self.dry_run:
                        DomainMetric.objects.create(
                            domain=domain,
                            timestamp=hour_start,
                            period='hourly',
                            cpu_millicores=int(aggregates['avg_cpu'] or 0),
                            cpu_limit_millicores=sample.cpu_limit_millicores,
                            memory_bytes=int(aggregates['avg_memory'] or 0),
                            memory_limit_bytes=sample.memory_limit_bytes,
                            http_requests=aggregates['sum_requests'] or 0,
                            http_2xx=aggregates['sum_2xx'] or 0,
                            http_3xx=aggregates['sum_3xx'] or 0,
                            http_4xx=aggregates['sum_4xx'] or 0,
                            http_5xx=aggregates['sum_5xx'] or 0,
                            avg_latency_ms=aggregates['avg_latency'] or 0,
                            bytes_in=aggregates['sum_bytes_in'] or 0,
                            bytes_out=aggregates['sum_bytes_out'] or 0,
                        )
                        self.stdout.write(f"Created hourly aggregate for {domain.domain_name} at {hour_start}")
                    else:
                        self.stdout.write(f"[DRY-RUN] Would create hourly aggregate for {domain.domain_name} at {hour_start}")

                hours_processed.add(hour_start)

    def aggregate_to_daily(self, now):
        """Aggregate hourly data into daily summaries."""
        cutoff = now - timedelta(days=1)

        for domain in Domain.objects.all():
            # Get hourly data that needs aggregation
            old_data = DomainMetric.objects.filter(
                domain=domain,
                period='hourly',
                timestamp__lt=cutoff
            ).order_by('timestamp')

            if not old_data.exists():
                continue

            # Group by day
            days_processed = set()
            for metric in old_data:
                day_start = metric.timestamp.replace(hour=0, minute=0, second=0, microsecond=0)

                if day_start in days_processed:
                    continue

                # Check if daily aggregate already exists
                if DomainMetric.objects.filter(
                    domain=domain,
                    period='daily',
                    timestamp=day_start
                ).exists():
                    days_processed.add(day_start)
                    continue

                # Get all hourly data for this day
                day_end = day_start + timedelta(days=1)
                day_data = DomainMetric.objects.filter(
                    domain=domain,
                    period='hourly',
                    timestamp__gte=day_start,
                    timestamp__lt=day_end
                )

                if day_data.exists():
                    aggregates = day_data.aggregate(
                        avg_cpu=Avg('cpu_millicores'),
                        avg_memory=Avg('memory_bytes'),
                        sum_requests=Sum('http_requests'),
                        sum_2xx=Sum('http_2xx'),
                        sum_3xx=Sum('http_3xx'),
                        sum_4xx=Sum('http_4xx'),
                        sum_5xx=Sum('http_5xx'),
                        avg_latency=Avg('avg_latency_ms'),
                        sum_bytes_in=Sum('bytes_in'),
                        sum_bytes_out=Sum('bytes_out'),
                    )

                    sample = day_data.first()

                    if not self.dry_run:
                        DomainMetric.objects.create(
                            domain=domain,
                            timestamp=day_start,
                            period='daily',
                            cpu_millicores=int(aggregates['avg_cpu'] or 0),
                            cpu_limit_millicores=sample.cpu_limit_millicores,
                            memory_bytes=int(aggregates['avg_memory'] or 0),
                            memory_limit_bytes=sample.memory_limit_bytes,
                            http_requests=aggregates['sum_requests'] or 0,
                            http_2xx=aggregates['sum_2xx'] or 0,
                            http_3xx=aggregates['sum_3xx'] or 0,
                            http_4xx=aggregates['sum_4xx'] or 0,
                            http_5xx=aggregates['sum_5xx'] or 0,
                            avg_latency_ms=aggregates['avg_latency'] or 0,
                            bytes_in=aggregates['sum_bytes_in'] or 0,
                            bytes_out=aggregates['sum_bytes_out'] or 0,
                        )
                        self.stdout.write(f"Created daily aggregate for {domain.domain_name} at {day_start}")
                    else:
                        self.stdout.write(f"[DRY-RUN] Would create daily aggregate for {domain.domain_name} at {day_start}")

                days_processed.add(day_start)

    def cleanup_old_data(self, now):
        """Delete old metrics according to retention policy."""
        # Delete 5-minute data older than 24 hours
        cutoff_5min = now - timedelta(hours=24)
        count_5min = DomainMetric.objects.filter(
            period='5min',
            timestamp__lt=cutoff_5min
        ).count()

        if not self.dry_run:
            DomainMetric.objects.filter(
                period='5min',
                timestamp__lt=cutoff_5min
            ).delete()
            if count_5min > 0:
                self.stdout.write(f"Deleted {count_5min} 5-minute records older than 24 hours")
        else:
            self.stdout.write(f"[DRY-RUN] Would delete {count_5min} 5-minute records older than 24 hours")

        # Delete hourly data older than 7 days
        cutoff_hourly = now - timedelta(days=7)
        count_hourly = DomainMetric.objects.filter(
            period='hourly',
            timestamp__lt=cutoff_hourly
        ).count()

        if not self.dry_run:
            DomainMetric.objects.filter(
                period='hourly',
                timestamp__lt=cutoff_hourly
            ).delete()
            if count_hourly > 0:
                self.stdout.write(f"Deleted {count_hourly} hourly records older than 7 days")
        else:
            self.stdout.write(f"[DRY-RUN] Would delete {count_hourly} hourly records older than 7 days")

        # Delete daily data older than 30 days
        cutoff_daily = now - timedelta(days=30)
        count_daily = DomainMetric.objects.filter(
            period='daily',
            timestamp__lt=cutoff_daily
        ).count()

        if not self.dry_run:
            DomainMetric.objects.filter(
                period='daily',
                timestamp__lt=cutoff_daily
            ).delete()
            if count_daily > 0:
                self.stdout.write(f"Deleted {count_daily} daily records older than 30 days")
        else:
            self.stdout.write(f"[DRY-RUN] Would delete {count_daily} daily records older than 30 days")

        total = count_5min + count_hourly + count_daily
        if total == 0:
            self.stdout.write(self.style.SUCCESS('No old metrics to clean up'))
        else:
            action = "Would clean up" if self.dry_run else "Cleaned up"
            self.stdout.write(self.style.SUCCESS(f'{action} {total} total records'))
