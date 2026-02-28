"""
Long-running metrics collector daemon.

Runs as a persistent pod, collecting metrics every 5 minutes
and performing cleanup hourly.

Usage:
    python manage.py metrics_collector

This replaces the CronJob approach with a single persistent process.
"""
import os
import time
import signal
import logging
from datetime import datetime
from django.core.management.base import BaseCommand
from django.core.management import call_command

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Long-running metrics collector daemon'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.running = True

    def add_arguments(self, parser):
        parser.add_argument(
            '--collection-interval',
            type=int,
            default=300,  # 5 minutes
            help='Interval between metric collections in seconds (default: 300)',
        )
        parser.add_argument(
            '--cleanup-interval',
            type=int,
            default=3600,  # 1 hour
            help='Interval between cleanup runs in seconds (default: 3600)',
        )

    def handle(self, *args, **options):
        collection_interval = options['collection_interval']
        cleanup_interval = options['cleanup_interval']

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        self.stdout.write(self.style.SUCCESS(
            f'Metrics collector started (collect every {collection_interval}s, cleanup every {cleanup_interval}s)'
        ))

        last_collection = 0
        last_cleanup = 0

        while self.running:
            now = time.time()

            # Run collection every collection_interval
            if now - last_collection >= collection_interval:
                self._run_collection()
                last_collection = now

            # Run cleanup every cleanup_interval
            if now - last_cleanup >= cleanup_interval:
                self._run_cleanup()
                last_cleanup = now

            # Sleep for a short interval to check signals
            time.sleep(10)

        self.stdout.write(self.style.SUCCESS('Metrics collector stopped'))

    def _handle_signal(self, signum, frame):
        """Handle shutdown signals gracefully."""
        self.stdout.write(self.style.WARNING(f'Received signal {signum}, shutting down...'))
        self.running = False

    def _run_collection(self):
        """Run the metrics collection."""
        try:
            self.stdout.write(f'[{datetime.now():%Y-%m-%d %H:%M:%S}] Running metrics collection...')
            call_command('collect_metrics', verbosity=0)
            self.stdout.write(self.style.SUCCESS('  Collection completed'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'  Collection failed: {e}'))
            logger.exception('Metrics collection failed')

    def _run_cleanup(self):
        """Run the metrics cleanup/aggregation."""
        try:
            self.stdout.write(f'[{datetime.now():%Y-%m-%d %H:%M:%S}] Running metrics cleanup...')
            call_command('cleanup_metrics', verbosity=0)
            self.stdout.write(self.style.SUCCESS('  Cleanup completed'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'  Cleanup failed: {e}'))
            logger.exception('Metrics cleanup failed')
