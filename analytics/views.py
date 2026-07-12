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

from django.contrib.auth.decorators import login_required
from django.db.models import Sum
from django.http import JsonResponse, HttpResponseForbidden
from django.shortcuts import render, get_object_or_404
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from dashboard.models import Domain
from dashboard.views.utils import COUNTRIES

from .models import (
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

    Lines for vhosts KubePanel does not host (panel itself, webmail,
    IP-based scans, ...) are silently skipped.
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
        vhost = (record.get('vhost') or '').lower().split(':')[0]
        domain_name = resolve_domain(vhost)
        if not domain_name:
            skipped += 1
            continue

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
        bot_category = classify_bot(ua)
        browser, os_name, device_class = parse_user_agent(ua, bot_category)
        referrer_domain, referrer_path = parse_referrer(
            record.get('http_referrer'), domain_hostnames[domain_name]
        )

        rows.append(AnalyticsRequest(
            timestamp=ts,
            domain_name=domain_name,
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


def _timeseries(domain_names, start, end, granularity):
    """Chart buckets: [{t, pageviews, visitors, requests, bandwidth}, ...]"""
    if granularity == 'hourly':
        qs = AnalyticsHourlyStat.objects.filter(
            domain_name__in=domain_names,
            period_start__gte=start, period_start__lte=end,
        )
    else:
        qs = AnalyticsDailyStat.objects.filter(
            domain_name__in=domain_names,
            period_start__gte=start, period_start__lte=end,
        )

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
    totals = AnalyticsDailyStat.objects.filter(
        domain_name__in=domain_names,
        period_start__gte=start.replace(hour=0, minute=0, second=0, microsecond=0),
        period_start__lte=end,
    ).aggregate(
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
    date_filter = {'domain_name__in': domain_names, 'date__gte': start_date, 'date__lte': end_date}

    pages = _top(
        AnalyticsPathStat.objects.filter(**date_filter),
        ['path'], {'views': 'views', 'visitors': 'visitors', 'entry_views': 'entry_views'}, limit,
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


def _analytics_payload(domain_names, range_key):
    start, end, granularity = _range_bounds(range_key)
    return {
        'summary': _summary(domain_names, start, end),
        'timeseries': _timeseries(domain_names, start, end, granularity),
        'dimensions': _dimensions(domain_names, start.date(), end.date()),
        'meta': {
            'range': range_key,
            'granularity': granularity,
            'start': start.isoformat(),
            'end': end.isoformat(),
        },
    }


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

    range_key = request.GET.get('range', 'day')
    if range_key not in VALID_RANGES:
        range_key = 'day'

    return JsonResponse(_analytics_payload([domain_obj.domain_name], range_key))


# ---------------------------------------------------------------------------
# Global dashboard (superuser)
# ---------------------------------------------------------------------------

@login_required(login_url="/dashboard/")
def global_analytics_page(request):
    """Render the cluster-wide analytics dashboard."""
    if not request.user.is_superuser:
        return HttpResponseForbidden("Only superusers can view global analytics.")

    return render(request, 'analytics/global_analytics.html')


@login_required(login_url="/dashboard/")
def global_analytics_api(request):
    """JSON API for the global dashboard: all domains + per-domain toplist."""
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Permission denied'}, status=403)

    range_key = request.GET.get('range', 'day')
    if range_key not in VALID_RANGES:
        range_key = 'day'

    domain_names = list(Domain.objects.values_list('domain_name', flat=True))
    payload = _analytics_payload(domain_names, range_key)

    # Per-domain toplist over the same range
    start, end, _ = _range_bounds(range_key)
    per_domain = (
        AnalyticsDailyStat.objects.filter(
            domain_name__in=domain_names,
            period_start__gte=start.replace(hour=0, minute=0, second=0, microsecond=0),
            period_start__lte=end,
        )
        .values('domain_name')
        .annotate(
            pageviews=Sum('pageviews'),
            visitors=Sum('visitors'),
            requests=Sum('requests'),
            bandwidth=Sum('bandwidth_bytes'),
        )
        .order_by('-pageviews')[:25]
    )
    payload['top_domains'] = list(per_domain)

    return JsonResponse(payload)
