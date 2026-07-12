"""
Roll up raw analytics requests into hourly/daily stats and per-day
dimension tables, then prune old data.

Run periodically (every 5 minutes) from the metrics-collector sidecar:
    python manage.py analytics_rollup

The command is stateless and idempotent: it recomputes every (domain,
period) that has raw rows inside the lookback window and upserts the
results, so overlapping or repeated runs are safe. Use --days to force
a full recompute further back (raw data is kept 14 days):
    python manage.py analytics_rollup --days 14

Retention policy (enforced here):
- raw requests: 14 days
- hourly stats: 90 days
- daily stats and dimension tables: kept forever
"""
import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone as dt_timezone

from django.core.management.base import BaseCommand
from django.db.models import Count, Q, Sum
from django.db.models.functions import TruncDate, TruncHour
from django.utils import timezone

from analytics.models import (
    AnalyticsRequest,
    AnalyticsHourlyStat,
    AnalyticsDailyStat,
    AnalyticsPathStat,
    AnalyticsReferrerStat,
    AnalyticsCountryStat,
    AnalyticsBrowserStat,
    AnalyticsIPStat,
)

logger = logging.getLogger(__name__)

RAW_RETENTION_DAYS = 14
HOURLY_RETENTION_DAYS = 90
LOOKBACK_HOURS = 3
TOP_IPS_PER_DAY = 100
MAX_PATH_LENGTH = 500

STAT_AGGREGATES = dict(
    total_requests=Count('id'),
    bandwidth=Sum('bytes_sent'),
    n_2xx=Count('id', filter=Q(status__gte=200, status__lt=300)),
    n_3xx=Count('id', filter=Q(status__gte=300, status__lt=400)),
    n_4xx=Count('id', filter=Q(status__gte=400, status__lt=500)),
    n_5xx=Count('id', filter=Q(status__gte=500, status__lt=600)),
    n_pageviews=Count('id', filter=Q(bot_category='human', is_page=True)),
    n_visitors=Count(
        'visitor_hash', distinct=True,
        filter=Q(bot_category='human', is_page=True),
    ),
    n_human=Count('id', filter=Q(bot_category='human')),
    n_search=Count('id', filter=Q(bot_category='search_engine')),
    n_ai=Count('id', filter=Q(bot_category='ai_bot')),
    n_otherbot=Count('id', filter=Q(bot_category='other_bot')),
)


def _stat_defaults(row):
    return {
        'requests': row['total_requests'] or 0,
        'bandwidth_bytes': row['bandwidth'] or 0,
        'hits_2xx': row['n_2xx'] or 0,
        'hits_3xx': row['n_3xx'] or 0,
        'hits_4xx': row['n_4xx'] or 0,
        'hits_5xx': row['n_5xx'] or 0,
        'pageviews': row['n_pageviews'] or 0,
        'visitors': row['n_visitors'] or 0,
        'human_requests': row['n_human'] or 0,
        'search_requests': row['n_search'] or 0,
        'ai_requests': row['n_ai'] or 0,
        'otherbot_requests': row['n_otherbot'] or 0,
    }


class Command(BaseCommand):
    help = 'Aggregate raw analytics requests into hourly/daily stats and prune old data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days', type=int, default=0,
            help='Recompute the last N full days instead of the incremental lookback window',
        )
        parser.add_argument(
            '--skip-cleanup', action='store_true',
            help='Only aggregate, do not prune old data',
        )

    def handle(self, *args, **options):
        now = timezone.now()

        if options['days'] > 0:
            window_start = now - timedelta(days=options['days'])
        else:
            window_start = now - timedelta(hours=LOOKBACK_HOURS)

        self.rollup_hourly(window_start, now)
        self.rollup_daily_and_dimensions(window_start, now)

        if not options['skip_cleanup']:
            self.cleanup(now)

    # ------------------------------------------------------------------
    # Hourly stats (pure SQL aggregation)
    # ------------------------------------------------------------------

    def rollup_hourly(self, window_start, now):
        rows = (
            AnalyticsRequest.objects
            .filter(timestamp__gte=window_start, timestamp__lte=now)
            .annotate(hour=TruncHour('timestamp'))
            .values('domain_name', 'hour')
            .annotate(**STAT_AGGREGATES)
        )

        count = 0
        for row in rows:
            AnalyticsHourlyStat.objects.update_or_create(
                domain_name=row['domain_name'],
                period_start=row['hour'],
                defaults=_stat_defaults(row),
            )
            count += 1
        if count:
            self.stdout.write(f"Upserted {count} hourly stat rows")

    # ------------------------------------------------------------------
    # Daily stats + dimension tables
    # ------------------------------------------------------------------

    def rollup_daily_and_dimensions(self, window_start, now):
        touched = list(
            AnalyticsRequest.objects
            .filter(timestamp__gte=window_start, timestamp__lte=now)
            .annotate(day=TruncDate('timestamp'))
            .values_list('domain_name', 'day')
            .distinct()
        )

        for domain_name, day in touched:
            self.rollup_day_stats(domain_name, day)
            self.rollup_day_dimensions(domain_name, day)

        if touched:
            self.stdout.write(f"Recomputed {len(touched)} (domain, day) rollups")

    def rollup_day_stats(self, domain_name, day):
        row = (
            AnalyticsRequest.objects
            .filter(domain_name=domain_name, timestamp__date=day)
            .aggregate(**STAT_AGGREGATES)
        )
        day_start = datetime(day.year, day.month, day.day, tzinfo=dt_timezone.utc)
        AnalyticsDailyStat.objects.update_or_create(
            domain_name=domain_name,
            period_start=day_start,
            defaults=_stat_defaults(row),
        )

    def rollup_day_dimensions(self, domain_name, day):
        """
        Recompute all dimension rows for one (domain, day) in a single
        ordered pass over the day's raw rows. Delete-and-recreate keeps
        the operation idempotent.
        """
        paths = defaultdict(lambda: {'views': 0, 'visitors': set(), 'entries': 0})
        referrers = defaultdict(lambda: {'views': 0, 'visitors': set()})
        countries = defaultdict(lambda: {'views': 0, 'visitors': set()})
        browsers = defaultdict(lambda: {'views': 0, 'visitors': set()})
        ips = defaultdict(lambda: {
            'requests': 0, 'bandwidth': 0, 'country': '', 'categories': Counter(),
        })
        seen_visitors = set()

        raw_rows = (
            AnalyticsRequest.objects
            .filter(domain_name=domain_name, timestamp__date=day)
            .order_by('timestamp')
            .values_list(
                'visitor_hash', 'path', 'referrer_domain', 'country_code',
                'browser', 'os', 'device_class', 'bot_category', 'is_page',
                'ip', 'bytes_sent',
            )
            .iterator(chunk_size=5000)
        )

        for (vhash, path, ref_domain, country, browser, os_name,
             device, bot_category, is_page, ip, bytes_sent) in raw_rows:
            ip_entry = ips[ip]
            ip_entry['requests'] += 1
            ip_entry['bandwidth'] += bytes_sent or 0
            ip_entry['country'] = ip_entry['country'] or country
            ip_entry['categories'][bot_category] += 1

            if bot_category != 'human' or not is_page:
                continue

            path_key = (path or '/')[:MAX_PATH_LENGTH]
            path_entry = paths[path_key]
            path_entry['views'] += 1
            path_entry['visitors'].add(vhash)
            if vhash not in seen_visitors:
                seen_visitors.add(vhash)
                path_entry['entries'] += 1

            if ref_domain:
                ref_entry = referrers[ref_domain]
                ref_entry['views'] += 1
                ref_entry['visitors'].add(vhash)

            if country:
                country_entry = countries[country]
                country_entry['views'] += 1
                country_entry['visitors'].add(vhash)

            browser_entry = browsers[(browser, os_name, device)]
            browser_entry['views'] += 1
            browser_entry['visitors'].add(vhash)

        day_filter = {'domain_name': domain_name, 'date': day}

        AnalyticsPathStat.objects.filter(**day_filter).delete()
        AnalyticsPathStat.objects.bulk_create([
            AnalyticsPathStat(
                **day_filter, path=path,
                views=entry['views'], visitors=len(entry['visitors']),
                entry_views=entry['entries'],
            )
            for path, entry in paths.items()
        ], batch_size=500)

        AnalyticsReferrerStat.objects.filter(**day_filter).delete()
        AnalyticsReferrerStat.objects.bulk_create([
            AnalyticsReferrerStat(
                **day_filter, referrer_domain=ref_domain,
                views=entry['views'], visitors=len(entry['visitors']),
            )
            for ref_domain, entry in referrers.items()
        ], batch_size=500)

        AnalyticsCountryStat.objects.filter(**day_filter).delete()
        AnalyticsCountryStat.objects.bulk_create([
            AnalyticsCountryStat(
                **day_filter, country_code=country,
                views=entry['views'], visitors=len(entry['visitors']),
            )
            for country, entry in countries.items()
        ], batch_size=500)

        AnalyticsBrowserStat.objects.filter(**day_filter).delete()
        AnalyticsBrowserStat.objects.bulk_create([
            AnalyticsBrowserStat(
                **day_filter, browser=browser, os=os_name, device_class=device,
                views=entry['views'], visitors=len(entry['visitors']),
            )
            for (browser, os_name, device), entry in browsers.items()
        ], batch_size=500)

        top_ips = sorted(
            ips.items(), key=lambda item: item[1]['requests'], reverse=True,
        )[:TOP_IPS_PER_DAY]
        AnalyticsIPStat.objects.filter(**day_filter).delete()
        AnalyticsIPStat.objects.bulk_create([
            AnalyticsIPStat(
                **day_filter, ip=ip,
                requests=entry['requests'], bandwidth_bytes=entry['bandwidth'],
                country_code=entry['country'],
                bot_category=entry['categories'].most_common(1)[0][0],
            )
            for ip, entry in top_ips
        ], batch_size=500)

    # ------------------------------------------------------------------
    # Retention
    # ------------------------------------------------------------------

    def cleanup(self, now):
        raw_cutoff = now - timedelta(days=RAW_RETENTION_DAYS)
        deleted_raw, _ = AnalyticsRequest.objects.filter(
            timestamp__lt=raw_cutoff
        ).delete()

        hourly_cutoff = now - timedelta(days=HOURLY_RETENTION_DAYS)
        deleted_hourly, _ = AnalyticsHourlyStat.objects.filter(
            period_start__lt=hourly_cutoff
        ).delete()

        if deleted_raw or deleted_hourly:
            self.stdout.write(self.style.SUCCESS(
                f"Pruned {deleted_raw} raw rows (>{RAW_RETENTION_DAYS}d) and "
                f"{deleted_hourly} hourly rows (>{HOURLY_RETENTION_DAYS}d)"
            ))
