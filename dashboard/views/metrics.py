"""
Domain metrics views - CPU, memory, HTTP statistics.

Provides time-series metrics visualization using Chart.js.
"""
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, HttpResponseForbidden
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from django.db.models import Sum, Avg, Max
from datetime import timedelta
from collections import defaultdict

from dashboard.models import Domain, DomainMetric


@login_required(login_url="/dashboard/")
def domain_metrics_page(request, domain):
    """Render metrics dashboard page with Chart.js graphs."""
    domain_obj = get_object_or_404(Domain, domain_name=domain)

    # Check ownership
    if not request.user.is_superuser and domain_obj.owner != request.user:
        return HttpResponseForbidden("You don't have permission to view these metrics.")

    return render(request, 'main/domain_metrics.html', {
        'domain': domain_obj,
    })


@login_required(login_url="/dashboard/")
def domain_metrics_api(request, domain):
    """Return metrics data for a domain (JSON API for Chart.js)."""
    domain_obj = get_object_or_404(Domain, domain_name=domain)

    # Check ownership
    if not request.user.is_superuser and domain_obj.owner != request.user:
        return JsonResponse({'error': 'Permission denied'}, status=403)

    # Get time range from query params
    hours = int(request.GET.get('hours', 24))
    period = request.GET.get('period', '5min')

    # Validate period
    if period not in ('5min', 'hourly', 'daily'):
        period = '5min'

    # Calculate cutoff time
    cutoff = timezone.now() - timedelta(hours=hours)

    # Query metrics
    metrics = DomainMetric.objects.filter(
        domain=domain_obj,
        period=period,
        timestamp__gte=cutoff
    ).order_by('timestamp')

    # Format for Chart.js
    data = {
        'labels': [m.timestamp.isoformat() for m in metrics],
        'cpu': {
            'values': [m.cpu_millicores for m in metrics],
            'limits': [m.cpu_limit_millicores for m in metrics],
            'percents': [m.cpu_percent for m in metrics],
        },
        'memory': {
            'values': [m.memory_mb for m in metrics],
            'limits': [m.memory_limit_mb for m in metrics],
            'percents': [m.memory_percent for m in metrics],
            'bytes': [m.memory_bytes for m in metrics],
        },
        'http': {
            'requests': [m.http_requests for m in metrics],
            'status_2xx': [m.http_2xx for m in metrics],
            'status_3xx': [m.http_3xx for m in metrics],
            'status_4xx': [m.http_4xx for m in metrics],
            'status_5xx': [m.http_5xx for m in metrics],
            'latency_ms': [m.avg_latency_ms for m in metrics],
        },
        'bandwidth': {
            'bytes_in': [m.bytes_in for m in metrics],
            'bytes_out': [m.bytes_out for m in metrics],
        },
        'meta': {
            'domain': domain_obj.domain_name,
            'period': period,
            'hours': hours,
            'count': len(metrics),
        }
    }

    return JsonResponse(data)


@login_required(login_url="/dashboard/")
def domain_metrics_summary(request, domain):
    """Return current/latest metrics summary for a domain."""
    domain_obj = get_object_or_404(Domain, domain_name=domain)

    # Check ownership
    if not request.user.is_superuser and domain_obj.owner != request.user:
        return JsonResponse({'error': 'Permission denied'}, status=403)

    # Get latest metric
    latest = DomainMetric.objects.filter(
        domain=domain_obj,
        period='5min'
    ).order_by('-timestamp').first()

    if not latest:
        return JsonResponse({
            'has_data': False,
            'message': 'No metrics data available yet'
        })

    # Get 24h totals
    cutoff_24h = timezone.now() - timedelta(hours=24)
    metrics_24h = DomainMetric.objects.filter(
        domain=domain_obj,
        period='5min',
        timestamp__gte=cutoff_24h
    )

    total_requests = sum(m.http_requests for m in metrics_24h)
    total_errors = sum(m.http_4xx + m.http_5xx for m in metrics_24h)
    avg_latency = sum(m.avg_latency_ms for m in metrics_24h) / max(len(metrics_24h), 1)

    return JsonResponse({
        'has_data': True,
        'latest': {
            'timestamp': latest.timestamp.isoformat(),
            'cpu_millicores': latest.cpu_millicores,
            'cpu_percent': latest.cpu_percent,
            'memory_mb': latest.memory_mb,
            'memory_percent': latest.memory_percent,
            'http_requests': latest.http_requests,
        },
        'last_24h': {
            'total_requests': total_requests,
            'total_errors': total_errors,
            'avg_latency_ms': round(avg_latency, 1),
        }
    })


# =============================================================================
# Global Metrics Views (Superuser Only)
# =============================================================================

@login_required(login_url="/dashboard/")
def global_metrics_page(request):
    """Render global metrics dashboard for superusers."""
    if not request.user.is_superuser:
        return HttpResponseForbidden("Only superusers can view global metrics.")

    return render(request, 'main/global_metrics.html')


@login_required(login_url="/dashboard/")
def global_metrics_api(request):
    """Return aggregated metrics for all domains (JSON API for Chart.js)."""
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Permission denied'}, status=403)

    # Get time range from query params
    hours = int(request.GET.get('hours', 24))
    period = request.GET.get('period', '5min')

    if period not in ('5min', 'hourly', 'daily'):
        period = '5min'

    cutoff = timezone.now() - timedelta(hours=hours)
    cutoff_24h = timezone.now() - timedelta(hours=24)

    # Get all domains
    domains = Domain.objects.all()
    total_domains = domains.count()

    # Get latest metrics for each domain (for current totals and top consumers)
    latest_metrics = []
    for domain in domains:
        latest = DomainMetric.objects.filter(
            domain=domain,
            period='5min'
        ).order_by('-timestamp').first()
        if latest:
            latest_metrics.append({
                'domain': domain.domain_name,
                'domain_id': domain.id,
                'cpu_millicores': latest.cpu_millicores,
                'cpu_limit': latest.cpu_limit_millicores,
                'cpu_percent': latest.cpu_percent,
                'memory_bytes': latest.memory_bytes,
                'memory_mb': latest.memory_mb,
                'memory_limit_mb': latest.memory_limit_mb,
                'memory_percent': latest.memory_percent,
            })

    # Calculate current totals
    total_cpu = sum(m['cpu_millicores'] for m in latest_metrics)
    total_memory_mb = sum(m['memory_mb'] for m in latest_metrics)

    # Get 24h request totals per domain
    domain_requests_24h = {}
    for domain in domains:
        metrics_24h = DomainMetric.objects.filter(
            domain=domain,
            period='5min',
            timestamp__gte=cutoff_24h
        ).aggregate(total=Sum('http_requests'))
        domain_requests_24h[domain.domain_name] = metrics_24h['total'] or 0

    total_requests_24h = sum(domain_requests_24h.values())

    # Top consumers
    top_cpu = sorted(latest_metrics, key=lambda x: x['cpu_millicores'], reverse=True)[:10]
    top_memory = sorted(latest_metrics, key=lambda x: x['memory_mb'], reverse=True)[:10]
    top_requests = sorted(
        [{'domain': k, 'requests_24h': v} for k, v in domain_requests_24h.items()],
        key=lambda x: x['requests_24h'],
        reverse=True
    )[:10]

    # Aggregate time series data
    all_metrics = DomainMetric.objects.filter(
        period=period,
        timestamp__gte=cutoff
    ).order_by('timestamp')

    # Group by timestamp
    ts_data = defaultdict(lambda: {
        'cpu': 0, 'memory': 0, 'requests': 0,
        'http_2xx': 0, 'http_3xx': 0, 'http_4xx': 0, 'http_5xx': 0,
        'bytes_in': 0, 'bytes_out': 0
    })

    for m in all_metrics:
        ts_key = m.timestamp.isoformat()
        ts_data[ts_key]['cpu'] += m.cpu_millicores
        ts_data[ts_key]['memory'] += m.memory_bytes
        ts_data[ts_key]['requests'] += m.http_requests
        ts_data[ts_key]['http_2xx'] += m.http_2xx
        ts_data[ts_key]['http_3xx'] += m.http_3xx
        ts_data[ts_key]['http_4xx'] += m.http_4xx
        ts_data[ts_key]['http_5xx'] += m.http_5xx
        ts_data[ts_key]['bytes_in'] += m.bytes_in
        ts_data[ts_key]['bytes_out'] += m.bytes_out

    # Sort by timestamp
    sorted_ts = sorted(ts_data.items(), key=lambda x: x[0])
    labels = [ts for ts, _ in sorted_ts]
    cpu_values = [d['cpu'] for _, d in sorted_ts]
    memory_values = [round(d['memory'] / (1024 * 1024), 1) for _, d in sorted_ts]  # Convert to MB
    request_values = [d['requests'] for _, d in sorted_ts]
    http_2xx = [d['http_2xx'] for _, d in sorted_ts]
    http_3xx = [d['http_3xx'] for _, d in sorted_ts]
    http_4xx = [d['http_4xx'] for _, d in sorted_ts]
    http_5xx = [d['http_5xx'] for _, d in sorted_ts]
    bytes_in = [d['bytes_in'] for _, d in sorted_ts]
    bytes_out = [d['bytes_out'] for _, d in sorted_ts]

    return JsonResponse({
        'summary': {
            'total_domains': total_domains,
            'total_cpu_millicores': total_cpu,
            'total_memory_mb': round(total_memory_mb, 1),
            'total_requests_24h': total_requests_24h,
        },
        'top_cpu': top_cpu,
        'top_memory': top_memory,
        'top_requests': top_requests,
        'timeseries': {
            'labels': labels,
            'cpu': cpu_values,
            'memory': memory_values,
            'requests': request_values,
            'http_2xx': http_2xx,
            'http_3xx': http_3xx,
            'http_4xx': http_4xx,
            'http_5xx': http_5xx,
            'bytes_in': bytes_in,
            'bytes_out': bytes_out,
        },
        'meta': {
            'period': period,
            'hours': hours,
            'data_points': len(labels),
        }
    })
