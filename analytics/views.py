"""
Analytics views: log ingestion (from Fluent Bit) and dashboard APIs.

Ingest:  POST /dashboard/api/analytics/ingest/   (token auth, no session)
Domain:  /dashboard/domains/<domain>/analytics/  (+ JSON API)
Global:  /dashboard/analytics/                   (+ JSON API, superuser)
"""
import hmac
import json
import logging
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone as dt_timezone

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q, Sum
from django.db.models.functions import TruncHour
from django.http import JsonResponse, HttpResponseForbidden
from django.shortcuts import render, get_object_or_404
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from dashboard.models import Domain
from dashboard.views.utils import COUNTRIES

from .models import (
    RAW_RETENTION_DAYS,
    HOURLY_RETENTION_DAYS,
    AnalyticsRequest,
    AnalyticsHourlyStat,
    AnalyticsDailyStat,
    AnalyticsPathStat,
    AnalyticsReferrerStat,
    AnalyticsCountryStat,
    AnalyticsBrowserStat,
    AnalyticsIPStat,
)
from .enrichment import (
    resolve_domain,
    get_vhost_map,
    lookup_country_code,
    classify_bot,
    parse_user_agent,
    visitor_hash,
    is_page_path,
    parse_referrer,
)

logger = logging.getLogger(__name__)

INGEST_TOKEN_ENV = 'ANALYTICS_INGEST_TOKEN'
INGEST_BATCH_SIZE = 500
COUNTRY_NAMES = dict(COUNTRIES)

VALID_RANGES = ('day', 'week', 'month', 'year')


# ---------------------------------------------------------------------------
# Ingestion endpoint (called by Fluent Bit)
# ---------------------------------------------------------------------------

def _check_ingest_token(request):
    expected = os.environ.get(INGEST_TOKEN_ENV, '')
    provided = request.headers.get('X-Analytics-Token', '')
    return bool(expected) and hmac.compare_digest(expected, provided)


def _parse_records(body):
    """Accept both Fluent Bit HTTP output formats: JSON array and NDJSON."""
    try:
        data = json.loads(body)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass

    records = []
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            if isinstance(record, dict):
                records.append(record)
        except json.JSONDecodeError:
            continue
    return records


def _parse_timestamp(record):
    """Log line timestamp: nginx $time_iso8601, else Fluent Bit epoch, else now."""
    time_str = record.get('time')
    if time_str:
        try:
            ts = datetime.fromisoformat(time_str)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=dt_timezone.utc)
            return ts.astimezone(dt_timezone.utc)
        except ValueError:
            pass
    date_val = record.get('date')
    if isinstance(date_val, (int, float)):
        return datetime.fromtimestamp(date_val, tz=dt_timezone.utc)
    return timezone.now()


def _to_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@csrf_exempt
@require_POST
def analytics_ingest(request):
    """
    Bulk-ingest enriched request rows from Fluent Bit.

    Every vhost is stored: hosted vhosts (incl. aliases and www) are
    unified under their canonical Domain name; anything else - the panel
    itself, manually deployed apps, scan traffic with bogus Host headers -
    keeps its raw vhost as the site key so admins can analyze it.
    """
    if not _check_ingest_token(request):
        return JsonResponse({'error': 'invalid token'}, status=403)

    try:
        body = request.body.decode('utf-8', errors='replace')
    except Exception:
        return JsonResponse({'error': 'unreadable body'}, status=400)

    records = _parse_records(body)
    if not records:
        return JsonResponse({'accepted': 0, 'skipped': 0})

    # hostnames per domain, for internal-referrer detection
    domain_hostnames = defaultdict(set)
    for hostname, domain_name in get_vhost_map().items():
        domain_hostnames[domain_name].add(hostname)

    rows = []
    skipped = 0
    for record in records:
        vhost = (record.get('vhost') or '').lower().split(':')[0][:253]
        if not vhost:
            skipped += 1
            continue
        domain_name = resolve_domain(vhost) or vhost

        # Real client IP: first hop of X-Forwarded-For; remote_addr
        # ($proxy_protocol_addr) is only set when proxy protocol is used.
        xff = record.get('x_forwarded_for') or ''
        ip = xff.split(',')[0].strip() or (record.get('remote_addr') or '').strip()
        if not ip:
            skipped += 1
            continue

        ts = _parse_timestamp(record)
        ua = record.get('http_user_agent') or ''
        if ua == '-':
            ua = ''
        path = record.get('path') or ''
        bot_category = classify_bot(ua, path)
        browser, os_name, device_class = parse_user_agent(ua, bot_category)
        referrer_domain, referrer_path = parse_referrer(
            record.get('http_referrer'),
            domain_hostnames.get(domain_name) or {vhost},
        )

        rows.append(AnalyticsRequest(
            timestamp=ts,
            domain_name=domain_name,
            vhost=vhost,
            ip=ip,
            visitor_hash=visitor_hash(ip, ua, vhost, ts.date()),
            country_code=lookup_country_code(ip),
            method=(record.get('method') or '')[:10],
            path=path,
            status=_to_int(record.get('status')),
            bytes_sent=_to_int(record.get('bytes_sent')),
            referrer_domain=referrer_domain,
            referrer_path=referrer_path,
            user_agent=ua,
            browser=browser,
            os=os_name,
            device_class=device_class,
            bot_category=bot_category,
            is_page=is_page_path(path),
        ))

    if rows:
        AnalyticsRequest.objects.bulk_create(rows, batch_size=INGEST_BATCH_SIZE)

    return JsonResponse({'accepted': len(rows), 'skipped': skipped})


# ---------------------------------------------------------------------------
# Range helpers
# ---------------------------------------------------------------------------

def _range_bounds(range_key):
    """
    (start, end, granularity) for a range keyword. All times UTC.
    day   -> today, hourly buckets
    week  -> last 7 days, daily buckets
    month -> last 30 days, daily buckets
    year  -> last 365 days, monthly buckets
    """
    now = timezone.now()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if range_key == 'day':
        return today, now, 'hourly'
    if range_key == 'week':
        return today - timedelta(days=6), now, 'daily'
    if range_key == 'month':
        return today - timedelta(days=29), now, 'daily'
    return today - timedelta(days=364), now, 'monthly'


def _parse_date_param(value):
    """Parse a YYYY-MM-DD query parameter, or None."""
    try:
        return datetime.strptime(value, '%Y-%m-%d').date()
    except (TypeError, ValueError):
        return None


def _request_range(request):
    """
    Resolve the requested time window: explicit ?start=&end= dates win
    over the ?range= presets. Returns (start, end, granularity, label).
    Granularity: single day -> hourly (daily if beyond hourly retention),
    spans up to ~3 months -> daily, longer -> monthly.
    """
    start_date = _parse_date_param(request.GET.get('start'))
    end_date = _parse_date_param(request.GET.get('end'))

    if start_date and end_date:
        if end_date < start_date:
            start_date, end_date = end_date, start_date
        now = timezone.now()
        start = datetime(start_date.year, start_date.month, start_date.day,
                         tzinfo=dt_timezone.utc)
        end = min(
            datetime(end_date.year, end_date.month, end_date.day,
                     23, 59, 59, tzinfo=dt_timezone.utc),
            now,
        )
        span_days = (end_date - start_date).days + 1
        if span_days == 1:
            hourly_cutoff = now - timedelta(days=HOURLY_RETENTION_DAYS)
            granularity = 'hourly' if start >= hourly_cutoff else 'daily'
        elif span_days <= 92:
            granularity = 'daily'
        else:
            granularity = 'monthly'
        return start, end, granularity, 'custom'

    range_key = request.GET.get('range', 'day')
    if range_key not in VALID_RANGES:
        range_key = 'day'
    start, end, granularity = _range_bounds(range_key)
    return start, end, granularity, range_key


def _site_filter(qs, domain_names):
    """Restrict a queryset to a site-key list; None means all sites."""
    if domain_names is None:
        return qs
    return qs.filter(domain_name__in=domain_names)


def _timeseries(domain_names, start, end, granularity):
    """Chart buckets: [{t, pageviews, visitors, requests, bandwidth}, ...]"""
    if granularity == 'hourly':
        qs = AnalyticsHourlyStat.objects.filter(
            period_start__gte=start, period_start__lte=end,
        )
    else:
        qs = AnalyticsDailyStat.objects.filter(
            period_start__gte=start, period_start__lte=end,
        )
    qs = _site_filter(qs, domain_names)

    buckets = defaultdict(lambda: {'pageviews': 0, 'visitors': 0, 'requests': 0, 'bandwidth': 0})
    for stat in qs:
        if granularity == 'monthly':
            key = stat.period_start.strftime('%Y-%m')
        else:
            key = stat.period_start.isoformat()
        buckets[key]['pageviews'] += stat.pageviews
        buckets[key]['visitors'] += stat.visitors
        buckets[key]['requests'] += stat.requests
        buckets[key]['bandwidth'] += stat.bandwidth_bytes

    return [
        {'t': key, **values}
        for key, values in sorted(buckets.items(), key=lambda item: item[0])
    ]


def _summary(domain_names, start, end):
    """Range totals from daily stats (visitors = sum of daily uniques)."""
    qs = AnalyticsDailyStat.objects.filter(
        period_start__gte=start.replace(hour=0, minute=0, second=0, microsecond=0),
        period_start__lte=end,
    )
    totals = _site_filter(qs, domain_names).aggregate(
        pageviews=Sum('pageviews'),
        visitors=Sum('visitors'),
        requests=Sum('requests'),
        bandwidth=Sum('bandwidth_bytes'),
        hits_4xx=Sum('hits_4xx'),
        hits_5xx=Sum('hits_5xx'),
        human=Sum('human_requests'),
        search=Sum('search_requests'),
        ai=Sum('ai_requests'),
        otherbot=Sum('otherbot_requests'),
    )
    return {
        'pageviews': totals['pageviews'] or 0,
        'visitors': totals['visitors'] or 0,
        'requests': totals['requests'] or 0,
        'bandwidth_bytes': totals['bandwidth'] or 0,
        'errors': (totals['hits_4xx'] or 0) + (totals['hits_5xx'] or 0),
        'traffic_mix': {
            'human': totals['human'] or 0,
            'search_engine': totals['search'] or 0,
            'ai_bot': totals['ai'] or 0,
            'other_bot': totals['otherbot'] or 0,
        },
    }


def _top(qs, group_fields, value_fields, limit=10):
    """Aggregate a dimension queryset into a top-N list of dicts."""
    rows = (
        qs.values(*group_fields)
        .annotate(**{name: Sum(field) for name, field in value_fields.items()})
        .order_by(f"-{list(value_fields)[0]}")[:limit]
    )
    return list(rows)


def _dimensions(domain_names, start_date, end_date, limit=10):
    date_filter = {'date__gte': start_date, 'date__lte': end_date}
    if domain_names is not None:
        date_filter['domain_name__in'] = domain_names

    pages = _top(
        AnalyticsPathStat.objects.filter(**date_filter),
        ['path'],
        {'views': 'views', 'visitors': 'visitors', 'entry_views': 'entry_views',
         'requests': 'requests', 'errors': 'errors'},
        limit,
    )
    entry_pages = _top(
        AnalyticsPathStat.objects.filter(**date_filter, entry_views__gt=0),
        ['path'], {'entry_views': 'entry_views', 'views': 'views'}, limit,
    )
    referrers = _top(
        AnalyticsReferrerStat.objects.filter(**date_filter),
        ['referrer_domain'], {'views': 'views', 'visitors': 'visitors'}, limit,
    )
    countries = _top(
        AnalyticsCountryStat.objects.filter(**date_filter).exclude(country_code=''),
        ['country_code'], {'views': 'views', 'visitors': 'visitors'}, limit,
    )
    for row in countries:
        code = row['country_code']
        row['country_name'] = COUNTRY_NAMES.get(code, code)
        row['flag_url'] = f"https://flagcdn.com/w40/{code.lower()}.png"

    browsers = _top(
        AnalyticsBrowserStat.objects.filter(**date_filter).exclude(browser=''),
        ['browser'], {'views': 'views', 'visitors': 'visitors'}, limit,
    )
    operating_systems = _top(
        AnalyticsBrowserStat.objects.filter(**date_filter).exclude(os=''),
        ['os'], {'views': 'views', 'visitors': 'visitors'}, limit,
    )
    devices = _top(
        AnalyticsBrowserStat.objects.filter(**date_filter).exclude(device_class__in=['', 'bot']),
        ['device_class'], {'views': 'views', 'visitors': 'visitors'}, limit,
    )
    top_ips = _top(
        AnalyticsIPStat.objects.filter(**date_filter),
        ['ip', 'bot_category', 'country_code'],
        {'requests': 'requests', 'bandwidth_bytes': 'bandwidth_bytes'}, limit,
    )

    return {
        'pages': pages,
        'entry_pages': entry_pages,
        'referrers': referrers,
        'countries': countries,
        'browsers': browsers,
        'operating_systems': operating_systems,
        'devices': devices,
        'top_ips': top_ips,
    }


def _analytics_payload(domain_names, start, end, granularity, range_label):
    return {
        'summary': _summary(domain_names, start, end),
        'timeseries': _timeseries(domain_names, start, end, granularity),
        'dimensions': _dimensions(domain_names, start.date(), end.date()),
        'meta': {
            'range': range_label,
            'granularity': granularity,
            'start': start.isoformat(),
            'end': end.isoformat(),
        },
    }


def _classify_site(site, hosted, panel_hosts):
    """hosted / panel / external label for a site key."""
    if site in hosted:
        return 'hosted'
    if site in panel_hosts:
        return 'panel'
    return 'external'


# ---------------------------------------------------------------------------
# Per-domain dashboard (owner or superuser)
# ---------------------------------------------------------------------------

@login_required(login_url="/dashboard/")
def domain_analytics_page(request, domain):
    """Render the single-page analytics dashboard for one domain."""
    domain_obj = get_object_or_404(Domain, domain_name=domain)
    if not request.user.is_superuser and domain_obj.owner != request.user:
        return HttpResponseForbidden("You don't have permission to view these analytics.")

    return render(request, 'analytics/domain_analytics.html', {
        'domain': domain_obj,
    })


@login_required(login_url="/dashboard/")
def domain_analytics_api(request, domain):
    """JSON API behind the per-domain analytics dashboard."""
    domain_obj = get_object_or_404(Domain, domain_name=domain)
    if not request.user.is_superuser and domain_obj.owner != request.user:
        return JsonResponse({'error': 'Permission denied'}, status=403)

    start, end, granularity, label = _request_range(request)
    return JsonResponse(_analytics_payload(
        [domain_obj.domain_name], start, end, granularity, label,
    ))


# ---------------------------------------------------------------------------
# Global dashboard (superuser)
# ---------------------------------------------------------------------------

@login_required(login_url="/dashboard/")
def global_analytics_page(request):
    """Render the cluster-wide analytics dashboard."""
    if not request.user.is_superuser:
        return HttpResponseForbidden("Only superusers can view global analytics.")

    return render(request, 'analytics/global_analytics.html')


def _panel_hostnames():
    """Panel-facing hostnames from settings (internal service names excluded)."""
    return {
        host for host in getattr(settings, 'ALLOWED_HOSTS', [])
        if not host.endswith('.svc.cluster.local')
    }


@login_required(login_url="/dashboard/")
def global_analytics_api(request):
    """
    JSON API for the global dashboard. Covers ALL ingress traffic - hosted
    domains, the panel itself, and external/unknown vhosts. Each site key
    is labeled hosted/panel/external; ?kind= filters to one label.
    """
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Permission denied'}, status=403)

    start, end, granularity, label = _request_range(request)
    kind = request.GET.get('kind', 'all')

    hosted = set(Domain.objects.values_list('domain_name', flat=True))
    panel_hosts = _panel_hostnames()

    # Site keys seen in this range, classified
    day_start = start.replace(hour=0, minute=0, second=0, microsecond=0)
    seen_sites = set(
        AnalyticsDailyStat.objects.filter(
            period_start__gte=day_start, period_start__lte=end,
        ).values_list('domain_name', flat=True).distinct()
    )
    site_kinds = {
        site: _classify_site(site, hosted, panel_hosts) for site in seen_sites
    }

    if kind in ('hosted', 'panel', 'external'):
        site_names = [s for s, k in site_kinds.items() if k == kind]
    else:
        kind = 'all'
        site_names = None  # no restriction

    payload = _analytics_payload(site_names, start, end, granularity, label)
    payload['meta']['kind'] = kind

    # Per-site toplist over the same range
    per_site_qs = AnalyticsDailyStat.objects.filter(
        period_start__gte=day_start, period_start__lte=end,
    )
    if site_names is not None:
        per_site_qs = per_site_qs.filter(domain_name__in=site_names)
    per_site = (
        per_site_qs
        .values('domain_name')
        .annotate(
            pageviews=Sum('pageviews'),
            visitors=Sum('visitors'),
            requests=Sum('requests'),
            bandwidth=Sum('bandwidth_bytes'),
            errors_4xx=Sum('hits_4xx'),
            errors_5xx=Sum('hits_5xx'),
        )
        .order_by('-requests')[:50]
    )
    payload['top_domains'] = [
        {**row,
         'errors': (row.pop('errors_4xx') or 0) + (row.pop('errors_5xx') or 0),
         'kind': site_kinds.get(row['domain_name'], 'external')}
        for row in per_site
    ]

    return JsonResponse(payload)


# ---------------------------------------------------------------------------
# Traffic Explorer (superuser) - raw-table forensics with vhost/path filters
# ---------------------------------------------------------------------------

STATUS_CLASSES = {
    '2xx': (200, 300),
    '3xx': (300, 400),
    '4xx': (400, 500),
    '5xx': (500, 600),
}

EXPLORER_SAMPLE_LIMIT = 100
EXPLORER_TOP_LIMIT = 25


@login_required(login_url="/dashboard/")
def traffic_explorer_page(request):
    """Render the raw-traffic explorer."""
    if not request.user.is_superuser:
        return HttpResponseForbidden("Only superusers can view the traffic explorer.")

    return render(request, 'analytics/traffic_explorer.html', {
        'raw_retention_days': RAW_RETENTION_DAYS,
        'countries': COUNTRIES,
    })


@login_required(login_url="/dashboard/")
def traffic_explorer_api(request):
    """
    Filtered aggregation over the raw request table (limited by the
    14-day raw retention). Filters: vhost (exact), path (substring),
    start/end dates, bot (category), status (2xx/3xx/4xx/5xx).
    """
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Permission denied'}, status=403)

    now = timezone.now()
    raw_horizon = now - timedelta(days=RAW_RETENTION_DAYS)

    start_date = _parse_date_param(request.GET.get('start'))
    end_date = _parse_date_param(request.GET.get('end'))
    if start_date and end_date:
        if end_date < start_date:
            start_date, end_date = end_date, start_date
        start = datetime(start_date.year, start_date.month, start_date.day,
                         tzinfo=dt_timezone.utc)
        end = min(
            datetime(end_date.year, end_date.month, end_date.day,
                     23, 59, 59, tzinfo=dt_timezone.utc),
            now,
        )
    else:
        start = now - timedelta(hours=24)
        end = now
    start = max(start, raw_horizon)

    qs = AnalyticsRequest.objects.filter(timestamp__gte=start, timestamp__lte=end)

    vhost = (request.GET.get('vhost') or '').strip().lower()
    if vhost:
        qs = qs.filter(vhost=vhost)
    path_query = (request.GET.get('path') or '').strip()
    if path_query:
        qs = qs.filter(path__icontains=path_query)
    bot = request.GET.get('bot') or ''
    if bot in {'human', 'search_engine', 'ai_bot', 'other_bot'}:
        qs = qs.filter(bot_category=bot)
    status_class = request.GET.get('status') or ''
    if status_class in STATUS_CLASSES:
        low, high = STATUS_CLASSES[status_class]
        qs = qs.filter(status__gte=low, status__lt=high)
    country = (request.GET.get('country') or '').strip().upper()
    if len(country) == 2:
        qs = qs.filter(country_code=country)

    error_filter = Q(status__gte=400)

    timeline_rows = (
        qs.annotate(hour=TruncHour('timestamp'))
        .values('hour')
        .annotate(requests=Count('id'), errors=Count('id', filter=error_filter))
        .order_by('hour')
    )
    status_mix = qs.aggregate(**{
        name: Count('id', filter=Q(status__gte=low, status__lt=high))
        for name, (low, high) in STATUS_CLASSES.items()
    })
    bot_mix = list(
        qs.values('bot_category').annotate(requests=Count('id')).order_by('-requests')
    )
    top_vhosts = list(
        qs.values('vhost')
        .annotate(requests=Count('id'), errors=Count('id', filter=error_filter))
        .order_by('-requests')[:EXPLORER_TOP_LIMIT]
    )
    top_paths = list(
        qs.values('path')
        .annotate(requests=Count('id'), errors=Count('id', filter=error_filter))
        .order_by('-requests')[:EXPLORER_TOP_LIMIT]
    )
    top_ips = list(
        qs.values('ip', 'country_code', 'bot_category')
        .annotate(requests=Count('id'), errors=Count('id', filter=error_filter))
        .order_by('-requests')[:EXPLORER_TOP_LIMIT]
    )
    top_referrers = list(
        qs.exclude(referrer_domain='')
        .values('referrer_domain')
        .annotate(requests=Count('id'))
        .order_by('-requests')[:EXPLORER_TOP_LIMIT]
    )
    sample = list(
        qs.order_by('-timestamp')
        .values('timestamp', 'vhost', 'ip', 'country_code', 'method', 'path',
                'status', 'bot_category', 'user_agent')[:EXPLORER_SAMPLE_LIMIT]
    )
    for row in sample:
        row['timestamp'] = row['timestamp'].isoformat()

    # Dropdown options: busiest vhosts in the window (unfiltered by vhost)
    options_qs = AnalyticsRequest.objects.filter(
        timestamp__gte=start, timestamp__lte=end,
    )
    vhost_options = [
        row['vhost']
        for row in options_qs.values('vhost')
        .annotate(c=Count('id')).order_by('-c')[:200]
    ]

    return JsonResponse({
        'timeline': [
            {'t': row['hour'].isoformat(),
             'requests': row['requests'], 'errors': row['errors']}
            for row in timeline_rows
        ],
        'status_mix': status_mix,
        'bot_mix': bot_mix,
        'top_vhosts': top_vhosts,
        'top_paths': top_paths,
        'top_ips': top_ips,
        'top_referrers': top_referrers,
        'sample': sample,
        'vhost_options': vhost_options,
        'total_requests': sum(status_mix.values()),
        'meta': {
            'start': start.isoformat(),
            'end': end.isoformat(),
            'raw_retention_days': RAW_RETENTION_DAYS,
            'filters': {
                'vhost': vhost, 'path': path_query,
                'bot': bot, 'status': status_class, 'country': country,
            },
        },
    })
