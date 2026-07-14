"""
Enrichment functions for raw ingress log lines.

Everything here is a pure function over the parsed log record so it can
be unit-tested without Kubernetes or a database. Called from the ingest
endpoint (analytics/views.py) for every accepted log line.
"""
import hashlib
import re
import time
from urllib.parse import urlparse

from django.conf import settings

import geoip2.database
import geoip2.errors

from dashboard.views.utils import GEOIP_DB_PATH, EXCLUDED_EXTENSIONS


# ---------------------------------------------------------------------------
# vhost -> domain_name resolution
# ---------------------------------------------------------------------------

_VHOST_CACHE = {'map': None, 'expires': 0.0}
_VHOST_CACHE_TTL = 60  # seconds


def get_vhost_map(force_refresh=False):
    """
    Map every hostname KubePanel serves (domain, aliases, www variants)
    to its Domain.domain_name. Cached for a short TTL - the ingest
    endpoint calls this for every batch.
    """
    now = time.monotonic()
    if not force_refresh and _VHOST_CACHE['map'] is not None and now < _VHOST_CACHE['expires']:
        return _VHOST_CACHE['map']

    from dashboard.models import Domain

    vhost_map = {}
    for domain in Domain.objects.prefetch_related('aliases').all():
        for hostname in domain.all_hostnames:
            hostname = hostname.lower()
            vhost_map[hostname] = domain.domain_name
            vhost_map[f"www.{hostname}"] = domain.domain_name

    _VHOST_CACHE['map'] = vhost_map
    _VHOST_CACHE['expires'] = now + _VHOST_CACHE_TTL
    return vhost_map


def resolve_domain(vhost):
    """Return the owning domain_name for a request vhost, or None if unknown."""
    if not vhost:
        return None
    return get_vhost_map().get(vhost.lower().split(':')[0])


# ---------------------------------------------------------------------------
# GeoIP
# ---------------------------------------------------------------------------

_GEOIP_READER = None


def _get_geoip_reader():
    global _GEOIP_READER
    if _GEOIP_READER is None:
        _GEOIP_READER = geoip2.database.Reader(GEOIP_DB_PATH)
    return _GEOIP_READER


def lookup_country_code(ip_address):
    """ISO 3166-1 alpha-2 country code for an IP, or '' if unknown."""
    try:
        response = _get_geoip_reader().country(ip_address)
        return (response.country.iso_code or '').upper()
    except (geoip2.errors.AddressNotFoundError, ValueError):
        return ''
    except Exception:
        return ''


# ---------------------------------------------------------------------------
# Bot classification
# ---------------------------------------------------------------------------
# Checked in order: AI bots first (many contain generic words like "bot"),
# then search engines, then generic bot heuristics. Extend the lists as
# new crawlers appear - substring match, case-insensitive.

AI_BOT_PATTERNS = [
    'gptbot', 'chatgpt-user', 'oai-searchbot',
    'claudebot', 'claude-web', 'claude-user', 'anthropic-ai',
    'perplexitybot', 'perplexity-user',
    'google-extended', 'applebot-extended',
    'ccbot', 'bytespider', 'amazonbot',
    'meta-externalagent', 'meta-externalfetcher', 'facebookbot',
    'cohere-ai', 'cohere-training-data-crawler',
    'diffbot', 'omgili', 'timpibot', 'imagesiftbot',
    'duckassistbot', 'mistralai-user', 'ai2bot', 'youbot',
]

SEARCH_ENGINE_PATTERNS = [
    'googlebot', 'google-inspectiontool', 'storebot-google', 'adsbot-google',
    'bingbot', 'adidxbot', 'bingpreview',
    'slurp', 'duckduckbot', 'duckduckgo',
    'baiduspider', 'yandexbot', 'yandeximages', 'yandexmobilebot',
    'sogou', 'exabot', 'seznambot', 'applebot', 'qwantbot', 'petalbot',
]

OTHER_BOT_PATTERNS = [
    'bot', 'crawler', 'spider', 'crawling', 'scraper', 'scrapy',
    'curl/', 'wget/', 'python-requests', 'python-urllib', 'go-http-client',
    'okhttp', 'libwww-perl', 'java/', 'httpclient', 'aiohttp',
    'headlesschrome', 'phantomjs', 'lighthouse',
    'uptimerobot', 'pingdom', 'statuscake', 'site24x7', 'checkly',
    'ahrefs', 'semrush', 'mj12bot', 'dotbot', 'screaming frog',
    'facebookexternalhit', 'whatsapp', 'telegrambot', 'slackbot',
    'discordbot', 'linkedinbot', 'twitterbot', 'pinterestbot',
    'feedfetcher', 'feedburner', 'rss', 'monitoring',
    'certbot', 'letsencrypt', "let's encrypt", 'acme',
]

# Requests to hidden/infrastructure paths are never human traffic, no
# matter what the user agent claims: ACME validation (/.well-known/
# acme-challenge/), repo/secret probes (/.git/config, /.env, /.aws/...).
# Rule: any path segment starting with a dot.
_INFRA_PATH_RE = re.compile(r'/\.')


def is_infra_path(path):
    """True for hidden-dotfile / infrastructure paths (/.well-known, /.git, /.env, ...)."""
    if not path:
        return False
    return bool(_INFRA_PATH_RE.search(path.split('?', 1)[0]))


def classify_bot(user_agent, path=None):
    """
    Classify a request into human / search_engine / ai_bot / other_bot.

    Primarily user-agent based; requests to infrastructure paths
    (see is_infra_path) are downgraded from human to other_bot - ACME
    validators and secret-probing scanners often send browser-like UAs.
    """
    if not user_agent or user_agent == '-':
        return 'other_bot'
    ua = user_agent.lower()
    for pattern in AI_BOT_PATTERNS:
        if pattern in ua:
            return 'ai_bot'
    for pattern in SEARCH_ENGINE_PATTERNS:
        if pattern in ua:
            return 'search_engine'
    for pattern in OTHER_BOT_PATTERNS:
        if pattern in ua:
            return 'other_bot'
    if path is not None and is_infra_path(path):
        return 'other_bot'
    return 'human'


# ---------------------------------------------------------------------------
# User agent parsing (browser / OS / device class)
# ---------------------------------------------------------------------------
# Order matters: more specific tokens are checked before the generic ones
# they embed (Edge before Chrome, Chrome before Safari).

_BROWSER_RULES = [
    ('Edge', re.compile(r'Edg(?:e|A|iOS)?/', re.I)),
    ('Opera', re.compile(r'OPR/|Opera', re.I)),
    ('Samsung Internet', re.compile(r'SamsungBrowser/', re.I)),
    ('Vivaldi', re.compile(r'Vivaldi/', re.I)),
    ('Brave', re.compile(r'Brave/', re.I)),
    ('UC Browser', re.compile(r'UCBrowser/', re.I)),
    ('Firefox', re.compile(r'Firefox/|FxiOS/', re.I)),
    ('Chrome', re.compile(r'Chrome/|CriOS/', re.I)),
    ('Safari', re.compile(r'Safari/', re.I)),
    ('Internet Explorer', re.compile(r'MSIE |Trident/', re.I)),
]

_OS_RULES = [
    ('iOS', re.compile(r'iPhone|iPad|iPod', re.I)),
    ('Android', re.compile(r'Android', re.I)),
    ('Windows', re.compile(r'Windows NT|Windows Phone', re.I)),
    ('macOS', re.compile(r'Macintosh|Mac OS X', re.I)),
    ('ChromeOS', re.compile(r'CrOS', re.I)),
    ('Linux', re.compile(r'Linux|X11', re.I)),
]

_MOBILE_RE = re.compile(r'Mobi|iPhone|iPod|Windows Phone', re.I)
_TABLET_RE = re.compile(r'iPad|Tablet', re.I)


def parse_user_agent(user_agent, bot_category='human'):
    """
    Return (browser, os, device_class) from a user agent string.

    Bots get device_class='bot' with empty browser/os so they never mix
    into the audience breakdowns.
    """
    if bot_category != 'human':
        return '', '', 'bot'
    if not user_agent or user_agent == '-':
        return '', '', ''

    browser = ''
    for name, pattern in _BROWSER_RULES:
        if pattern.search(user_agent):
            browser = name
            break

    os_name = ''
    for name, pattern in _OS_RULES:
        if pattern.search(user_agent):
            os_name = name
            break

    if _TABLET_RE.search(user_agent):
        device_class = 'tablet'
    elif _MOBILE_RE.search(user_agent) or (os_name == 'Android' and 'Mobile' in user_agent):
        device_class = 'mobile'
    else:
        device_class = 'desktop'

    return browser, os_name, device_class


# ---------------------------------------------------------------------------
# Visitor hash
# ---------------------------------------------------------------------------

def _daily_salt(date):
    """
    Deterministic per-day salt derived from SECRET_KEY - rotates at UTC
    midnight, so visitor hashes cannot be correlated across days and no
    salt storage is needed.
    """
    return hashlib.sha256(
        f"{settings.SECRET_KEY}:analytics:{date.isoformat()}".encode()
    ).hexdigest()


def visitor_hash(ip, user_agent, vhost, date):
    """Anonymous daily visitor identifier: sha256(salt + ip + ua + vhost)."""
    raw = f"{_daily_salt(date)}|{ip}|{user_agent}|{vhost}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Request classification helpers
# ---------------------------------------------------------------------------

def is_page_path(path):
    """
    True for page-like requests - everything except static assets.
    Uses the same extension list as the live traffic views.
    """
    if not path:
        return False
    clean = path.split('?', 1)[0].lower()
    return not any(clean.endswith(ext) for ext in EXCLUDED_EXTENSIONS)


def parse_referrer(referer, own_hostnames):
    """
    Split a Referer header into (referrer_domain, referrer_path).

    Internal navigation (referrer on one of the site's own hostnames)
    and empty referrers return ('', '') - only external sources count.
    """
    if not referer or referer == '-':
        return '', ''
    try:
        parsed = urlparse(referer)
    except ValueError:
        return '', ''
    host = (parsed.hostname or '').lower()
    if not host:
        return '', ''
    if host in own_hostnames or host.removeprefix('www.') in own_hostnames:
        return '', ''
    return host[:253], parsed.path or ''
