"""
Server-side analytics models.

Data flow:
  ingress-nginx JSON logs -> Fluent Bit -> analytics_ingest view
  -> AnalyticsRequest (raw, 14 day retention)
  -> analytics_rollup command
  -> AnalyticsHourlyStat (90 days) / AnalyticsDailyStat (forever)
     + per-day dimension tables (paths, referrers, countries, browsers, IPs)

All models live in the separate 'analytics' database (see router.py) and
reference domains by domain_name string - cross-database foreign keys to
dashboard.Domain are not possible.

Unique visitors are counted per day with a daily-rotating salted hash
(no cookies, no stored PII in aggregates). Multi-day visitor totals are
sums of daily uniques - the same semantics Plausible uses.
"""
from django.db import models


BOT_CATEGORY_CHOICES = [
    ('human', 'Human'),
    ('search_engine', 'Search Engine'),
    ('ai_bot', 'AI Bot'),
    ('other_bot', 'Other Bot'),
]


class AnalyticsRequest(models.Model):
    """
    One raw HTTP request from the ingress access log, enriched at ingest
    time (GeoIP, UA parsing, bot classification, visitor hash).

    Retention: 14 days (pruned by analytics_rollup). Rollup tables are
    the long-term store; this table also powers abuse investigation
    (raw IPs are visible here and in AnalyticsIPStat).
    """
    timestamp = models.DateTimeField(db_index=True)
    domain_name = models.CharField(max_length=253, db_index=True)

    # Client
    ip = models.GenericIPAddressField()
    visitor_hash = models.CharField(
        max_length=64,
        help_text="sha256(daily_salt + ip + user_agent + vhost) - rotates daily"
    )
    country_code = models.CharField(max_length=2, blank=True, default='')

    # Request
    method = models.CharField(max_length=10, blank=True, default='')
    path = models.TextField(blank=True, default='')
    status = models.IntegerField(default=0)
    bytes_sent = models.BigIntegerField(default=0)
    referrer_domain = models.CharField(max_length=253, blank=True, default='')
    referrer_path = models.TextField(blank=True, default='')

    # User agent
    user_agent = models.TextField(blank=True, default='')
    browser = models.CharField(max_length=50, blank=True, default='')
    os = models.CharField(max_length=50, blank=True, default='')
    device_class = models.CharField(max_length=20, blank=True, default='')
    bot_category = models.CharField(
        max_length=20, choices=BOT_CATEGORY_CHOICES, default='human'
    )

    # True for page-like requests (not static assets) - the basis of pageviews
    is_page = models.BooleanField(default=True)

    class Meta:
        indexes = [
            models.Index(fields=['domain_name', '-timestamp']),
            models.Index(fields=['-timestamp']),
        ]

    def __str__(self):
        return f"{self.domain_name} {self.method} {self.path} [{self.status}] @ {self.timestamp:%Y-%m-%d %H:%M:%S}"


class AnalyticsStatBase(models.Model):
    """Shared fields for hourly and daily per-domain aggregates."""
    domain_name = models.CharField(max_length=253, db_index=True)
    period_start = models.DateTimeField(db_index=True)

    # Totals (all requests, including bots and static files)
    requests = models.IntegerField(default=0)
    bandwidth_bytes = models.BigIntegerField(default=0)
    hits_2xx = models.IntegerField(default=0)
    hits_3xx = models.IntegerField(default=0)
    hits_4xx = models.IntegerField(default=0)
    hits_5xx = models.IntegerField(default=0)

    # Human traffic (bot_category='human')
    pageviews = models.IntegerField(
        default=0, help_text="Human page requests (is_page=True)"
    )
    visitors = models.IntegerField(
        default=0, help_text="Distinct human visitor hashes in this period"
    )

    # Traffic mix - request counts per bot category
    human_requests = models.IntegerField(default=0)
    search_requests = models.IntegerField(default=0)
    ai_requests = models.IntegerField(default=0)
    otherbot_requests = models.IntegerField(default=0)

    class Meta:
        abstract = True

    def __str__(self):
        return f"{self.domain_name} @ {self.period_start:%Y-%m-%d %H:%M}"


class AnalyticsHourlyStat(AnalyticsStatBase):
    """Per-domain, per-hour aggregate. Retention: 90 days."""

    class Meta:
        ordering = ['-period_start']
        unique_together = ['domain_name', 'period_start']
        indexes = [
            models.Index(fields=['domain_name', 'period_start']),
        ]


class AnalyticsDailyStat(AnalyticsStatBase):
    """Per-domain, per-day aggregate. Kept forever."""

    class Meta:
        ordering = ['-period_start']
        unique_together = ['domain_name', 'period_start']
        indexes = [
            models.Index(fields=['domain_name', 'period_start']),
        ]


class AnalyticsDimensionBase(models.Model):
    """
    Shared fields for per-day dimension rollups.

    Dimension tables count HUMAN traffic only (the GA-comparable numbers);
    bot pressure is visible in the traffic mix and in AnalyticsIPStat.
    """
    domain_name = models.CharField(max_length=253, db_index=True)
    date = models.DateField(db_index=True)
    views = models.IntegerField(default=0, help_text="Human pageviews")
    visitors = models.IntegerField(default=0, help_text="Distinct human visitors")

    class Meta:
        abstract = True


class AnalyticsPathStat(AnalyticsDimensionBase):
    """Top pages per domain per day, including entry-page counts."""
    path = models.CharField(max_length=500)
    entry_views = models.IntegerField(
        default=0,
        help_text="Visitors whose first pageview of the day was this path"
    )

    class Meta:
        ordering = ['-date', '-views']
        unique_together = ['domain_name', 'date', 'path']

    def __str__(self):
        return f"{self.domain_name} {self.date} {self.path}: {self.views}"


class AnalyticsReferrerStat(AnalyticsDimensionBase):
    """Top referrer domains per domain per day (external referrers only)."""
    referrer_domain = models.CharField(max_length=253)

    class Meta:
        ordering = ['-date', '-views']
        unique_together = ['domain_name', 'date', 'referrer_domain']

    def __str__(self):
        return f"{self.domain_name} {self.date} {self.referrer_domain}: {self.views}"


class AnalyticsCountryStat(AnalyticsDimensionBase):
    """Visitor countries per domain per day (GeoIP)."""
    country_code = models.CharField(max_length=2)

    class Meta:
        ordering = ['-date', '-views']
        unique_together = ['domain_name', 'date', 'country_code']

    def __str__(self):
        return f"{self.domain_name} {self.date} {self.country_code}: {self.views}"


class AnalyticsBrowserStat(AnalyticsDimensionBase):
    """Browser / OS / device breakdown per domain per day."""
    browser = models.CharField(max_length=50, blank=True, default='')
    os = models.CharField(max_length=50, blank=True, default='')
    device_class = models.CharField(max_length=20, blank=True, default='')

    class Meta:
        ordering = ['-date', '-views']
        unique_together = ['domain_name', 'date', 'browser', 'os', 'device_class']

    def __str__(self):
        return f"{self.domain_name} {self.date} {self.browser}/{self.os}: {self.views}"


class AnalyticsIPStat(models.Model):
    """
    Top client IPs per domain per day.

    Unlike the other dimension tables this counts ALL traffic (including
    bots) - its purpose is spotting scrapers, brute-force sources and
    other per-IP anomalies, not audience measurement.
    """
    domain_name = models.CharField(max_length=253, db_index=True)
    date = models.DateField(db_index=True)
    ip = models.GenericIPAddressField()
    requests = models.IntegerField(default=0)
    bandwidth_bytes = models.BigIntegerField(default=0)
    country_code = models.CharField(max_length=2, blank=True, default='')
    bot_category = models.CharField(
        max_length=20, choices=BOT_CATEGORY_CHOICES, default='human',
        help_text="Most frequent category seen for this IP on this day"
    )

    class Meta:
        ordering = ['-date', '-requests']
        unique_together = ['domain_name', 'date', 'ip']

    def __str__(self):
        return f"{self.domain_name} {self.date} {self.ip}: {self.requests}"
