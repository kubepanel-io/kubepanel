from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.core.validators import MinValueValidator, MaxValueValidator
from django.core.exceptions import ValidationError
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
from django.db.models.signals import post_save
from django.dispatch import receiver
import re

def validate_not_empty(value):
    if isinstance(value, str) and value.strip() == "":
        raise ValidationError('This field cannot be an empty string.')

class Package(models.Model):
    name = models.CharField(max_length=255, unique=True)
    max_storage_size = models.IntegerField(default=1, validators=[MinValueValidator(1), MaxValueValidator(10000)])
    max_cpu = models.IntegerField(default=500, validators=[MinValueValidator(100), MaxValueValidator(4000)])
    max_memory = models.IntegerField(default=256, validators=[MinValueValidator(32), MaxValueValidator(4096)])
    max_mail_users = models.IntegerField(null=True, blank=True)
    max_mail_aliases = models.IntegerField(null=True, blank=True)
    max_domain_aliases = models.IntegerField(null=True, blank=True)

    def __str__(self):
        return self.name

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    package = models.ForeignKey(Package, on_delete=models.PROTECT, null=True, blank=True)

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()

class PhpImage(models.Model):
    """DEPRECATED: Use WorkloadVersion instead. Kept for migration compatibility."""
    version = models.CharField(max_length=50, unique=True)
    repository_url = models.CharField(max_length=255)

    def __str__(self):
        return self.repository_url


class WorkloadType(models.Model):
    """
    Admin-configurable workload types (PHP, Python, Node.js, Django, etc.)

    Each type defines how the app container runs and connects to nginx.
    """
    PROXY_MODE_CHOICES = [
        ('fastcgi', 'FastCGI (PHP-FPM)'),
        ('http', 'HTTP Proxy'),
        ('uwsgi', 'uWSGI Protocol'),
    ]

    name = models.CharField(
        max_length=50,
        unique=True,
        help_text="Display name (e.g., 'PHP', 'Python', 'Node.js')"
    )
    slug = models.SlugField(
        max_length=50,
        unique=True,
        help_text="URL-safe identifier (e.g., 'php', 'python', 'nodejs')"
    )
    description = models.TextField(
        blank=True,
        help_text="Description of this workload type"
    )
    icon = models.CharField(
        max_length=50,
        blank=True,
        help_text="CSS class or emoji for UI display"
    )

    # Container configuration
    app_port = models.IntegerField(
        default=9000,
        help_text="Port the app container listens on (e.g., 9001 for PHP-FPM, 8000 for Python)"
    )
    proxy_mode = models.CharField(
        max_length=20,
        choices=PROXY_MODE_CHOICES,
        default='fastcgi',
        help_text="How nginx connects to the app container"
    )

    # Default resource settings
    default_cpu_limit = models.IntegerField(
        default=500,
        validators=[MinValueValidator(100), MaxValueValidator(4000)],
        help_text="Default CPU limit in millicores"
    )
    default_memory_limit = models.IntegerField(
        default=256,
        validators=[MinValueValidator(32), MaxValueValidator(4096)],
        help_text="Default memory limit in MB"
    )

    # Ordering and status
    display_order = models.IntegerField(
        default=0,
        help_text="Order in UI dropdowns (lower = first)"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this type is available for selection"
    )

    class Meta:
        ordering = ['display_order', 'name']
        verbose_name = "Workload Type"
        verbose_name_plural = "Workload Types"

    def __str__(self):
        return self.name


class WorkloadVersion(models.Model):
    """
    Specific versions available for each workload type.

    Admin configures the full container image URL for each version.
    """
    workload_type = models.ForeignKey(
        WorkloadType,
        on_delete=models.CASCADE,
        related_name='versions',
        help_text="Parent workload type"
    )
    version = models.CharField(
        max_length=50,
        help_text="Version string (e.g., '8.2', '3.11', '20')"
    )

    # Full image URL (admin-configured)
    image_url = models.CharField(
        max_length=500,
        help_text="Full container image URL (e.g., docker.io/kubepanel/php82:v1.0)"
    )

    # Version-specific defaults (override type defaults if set)
    default_cpu_limit = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(100), MaxValueValidator(4000)],
        help_text="Override CPU limit for this version (leave blank to use type default)"
    )
    default_memory_limit = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(32), MaxValueValidator(4096)],
        help_text="Override memory limit for this version (leave blank to use type default)"
    )

    # Ordering and status
    display_order = models.IntegerField(
        default=0,
        help_text="Order in UI dropdowns (lower = first)"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this version is available for selection"
    )
    is_default = models.BooleanField(
        default=False,
        help_text="Default version for this workload type"
    )

    class Meta:
        ordering = ['workload_type', 'display_order', '-version']
        unique_together = ['workload_type', 'version']
        verbose_name = "Workload Version"
        verbose_name_plural = "Workload Versions"

    def __str__(self):
        return f"{self.workload_type.name} {self.version}"

    @property
    def effective_cpu_limit(self):
        """Get CPU limit, falling back to type default."""
        return self.default_cpu_limit or self.workload_type.default_cpu_limit

    @property
    def effective_memory_limit(self):
        """Get memory limit, falling back to type default."""
        return self.default_memory_limit or self.workload_type.default_memory_limit

    def save(self, *args, **kwargs):
        # If this is being set as default, unset other defaults for this type
        if self.is_default:
            WorkloadVersion.objects.filter(
                workload_type=self.workload_type,
                is_default=True
            ).exclude(pk=self.pk).update(is_default=False)
        super().save(*args, **kwargs)


class Domain(models.Model):
    """
    Domain model - business logic and ownership tracking.
    
    Infrastructure details (secrets, ports, status) are managed by the 
    KubePanel operator and stored in Kubernetes (Domain CR + Secrets).
    
    This model handles:
    - Ownership (which user owns this domain)
    - Package limit enforcement (storage, CPU, memory quotas)
    - Relationships to other Django models (MailUser, DomainAlias, etc.)
    """
    
    # === Core Identity ===
    domain_name = models.CharField(
        max_length=253, 
        unique=True, 
        validators=[validate_not_empty],
        help_text="Primary domain name (e.g., example.com)"
    )
    title = models.CharField(
        max_length=255,
        help_text="Human-readable display name"
    )
    
    # === Ownership ===
    owner = models.ForeignKey(
        User, 
        on_delete=models.PROTECT,
        help_text="User who owns this domain"
    )
    
    # === Resource Allocation (for package limit enforcement) ===
    storage_size = models.IntegerField(
        default=5, 
        validators=[MinValueValidator(1), MaxValueValidator(10000)],
        help_text="Storage size in GB"
    )
    cpu_limit = models.IntegerField(
        default=500, 
        validators=[MinValueValidator(100), MaxValueValidator(4000)],
        help_text="CPU limit in millicores"
    )
    mem_limit = models.IntegerField(
        default=256, 
        validators=[MinValueValidator(32), MaxValueValidator(4096)],
        help_text="Memory limit in MB"
    )
    
    # === Workload Configuration ===
    workload_version = models.ForeignKey(
        WorkloadVersion,
        on_delete=models.PROTECT,
        related_name='domains',
        null=True,  # Nullable during migration, will be made required later
        blank=True,
        help_text="Workload type and version for this domain"
    )

    # DEPRECATED: Keep for migration compatibility
    php_image = models.ForeignKey(
        PhpImage,
        on_delete=models.PROTECT,
        related_name='domains',
        null=True,  # Made nullable for migration
        blank=True,
        help_text="DEPRECATED: Use workload_version instead"
    )

    # === Timestamps ===
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['domain_name']

    def __str__(self):
        return self.domain_name

    def clean(self):
        """Validate package limits."""
        super().clean()
        pkg = self.owner.profile.package
        if pkg is None:
            return
        
        # Get other domains for this user
        domains = Domain.objects.filter(owner=self.owner)
        if self.pk:
            domains = domains.exclude(pk=self.pk)
        
        # Check storage limit
        total_storage = sum(d.storage_size for d in domains) + self.storage_size
        if total_storage > pkg.max_storage_size:
            raise ValidationError({
                'storage_size': f"Total storage ({total_storage} GB) exceeds package limit ({pkg.max_storage_size} GB)."
            })
        
        # Check CPU limit
        total_cpu = sum(d.cpu_limit for d in domains) + self.cpu_limit
        if total_cpu > pkg.max_cpu:
            raise ValidationError({
                'cpu_limit': f"Total CPU ({total_cpu}m) exceeds package limit ({pkg.max_cpu}m)."
            })
        
        # Check memory limit
        total_mem = sum(d.mem_limit for d in domains) + self.mem_limit
        if total_mem > pkg.max_memory:
            raise ValidationError({
                'mem_limit': f"Total memory ({total_mem} MB) exceeds package limit ({pkg.max_memory} MB)."
            })
        
        # Check workload version (or php_image during migration)
        if self.workload_version_id is None and self.php_image_id is None:
            raise ValidationError({
                'workload_version': 'A workload type and version must be selected.'
            })
        
        # Check domain aliases limit
        if pkg.max_domain_aliases is not None:
            existing_aliases = sum(d.aliases.count() for d in domains)
            new_aliases = self.aliases.count() if self.pk else 0
            total_aliases = existing_aliases + new_aliases
            if total_aliases > pkg.max_domain_aliases:
                raise ValidationError({
                    'aliases': f"Total domain aliases ({total_aliases}) exceed package limit ({pkg.max_domain_aliases})."
                })
        
        # Check mail users limit
        if pkg.max_mail_users is not None:
            from .models import MailUser
            total_mail_users = MailUser.objects.filter(domain__owner=self.owner).count()
            if total_mail_users > pkg.max_mail_users:
                raise ValidationError({
                    'mail_users': f"Total mail users ({total_mail_users}) exceed package limit ({pkg.max_mail_users})."
                })

    @property
    def cr_name(self) -> str:
        """
        Get the Kubernetes CR name for this domain.
        
        e.g., 'example.com' -> 'example-com'
        """
        sanitized = re.sub(r'[^a-z0-9-]', '-', self.domain_name.lower())
        sanitized = re.sub(r'-+', '-', sanitized)
        return sanitized.strip('-')

    @property
    def namespace(self) -> str:
        """
        Get the Kubernetes namespace for this domain.
        
        e.g., 'example.com' -> 'dom-example-com'
        """
        return f"dom-{self.cr_name}"

    @property
    def all_hostnames(self):
        """Get all hostnames (domain + aliases)."""
        names = [self.domain_name]
        names += [alias.alias_name for alias in self.aliases.all()]
        return names

    @property
    def server_name_directive(self):
        """Get nginx server_name directive value."""
        return " ".join(self.all_hostnames)


# Alias for migrations compatibility
Domain.validate_not_empty = validate_not_empty


class DomainAlias(models.Model):
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='aliases')
    alias_name = models.CharField(max_length=255, unique=True, validators=[validate_not_empty])
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Domain Alias"
        verbose_name_plural = "Domain Aliases"
        ordering = ['domain__domain_name', 'alias_name']

    def __str__(self):
        return f"{self.alias_name} → {self.domain.domain_name}"


class CloudflareAPIToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    api_token = models.TextField()

    def __str__(self):
        return f"{self.user.username} - {self.name}"


class DNSZone(models.Model):
    name = models.CharField(max_length=253)
    zone_id = models.CharField(max_length=64)
    token = models.ForeignKey(CloudflareAPIToken, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.zone_id})"


class DNSRecord(models.Model):
    RECORD_TYPES = [
        ("A", "A"),
        ("AAAA", "AAAA"),
        ("CNAME", "CNAME"),
        ("TXT", "TXT"),
        ("MX", "MX"),
        ("NS", "NS"),
        ("SRV", "SRV"),
    ]

    zone = models.ForeignKey("DNSZone", on_delete=models.CASCADE, related_name="dns_records")
    record_type = models.CharField(max_length=10, choices=RECORD_TYPES)
    name = models.CharField(max_length=253)
    content = models.TextField(db_default="")
    ttl = models.IntegerField(default=120)
    proxied = models.BooleanField(default=False)
    priority = models.IntegerField(null=True, blank=True)
    cf_record_id = models.CharField(max_length=64, null=True, blank=True)

    def __str__(self):
        return f"{self.record_type} {self.name} -> {self.content}"


class ClusterIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    description = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"{self.ip_address} ({self.description or 'No Description'})"


class MailUser(models.Model):
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='mail_users')
    local_part = models.CharField(max_length=64)  # e.g. "info"
    password = models.CharField(max_length=255)   # store hashed value
    active = models.BooleanField(default=True)

    @property
    def email(self):
        return f"{self.local_part}@{self.domain.domain_name}"

    @property
    def aliases(self):
        # return all active MailAlias objects that forward *to* this mailbox
        return MailAlias.objects.filter(
            destination__iexact=self.email,
            active=True
        )

    def __str__(self):
        return self.email


class MailAlias(models.Model):
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='mail_aliases')
    source = models.CharField(max_length=255)      # e.g. "alias@example.com"
    destination = models.CharField(max_length=255) # e.g. "real@example.com"
    active = models.BooleanField(default=True)


class LogEntry(models.Model):
    LEVEL_CHOICES = [
        ('DEBUG', 'Debug'),
        ('INFO', 'Info'),
        ('WARNING', 'Warning'),
        ('ERROR', 'Error'),
        ('CRITICAL', 'Critical'),
    ]

    timestamp      = models.DateTimeField(auto_now_add=True)
    content_type   = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        related_name='dashboard_log_entries'
    )
    object_id      = models.PositiveIntegerField()
    content_object = GenericForeignKey('content_type', 'object_id')

    actor = models.CharField(
        max_length=100,
        help_text="Identifier of the actor (e.g. 'user:alice', 'backup_cron')"
    )
    user = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='dashboard_user_log_entries',
        help_text="Optional link to the authenticated user"
    )

    level   = models.CharField(max_length=10, choices=LEVEL_CHOICES, default='INFO')
    message = models.TextField()
    data    = models.JSONField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return (
            f"[{self.level}] {self.timestamp:%Y-%m-%d %H:%M:%S} "
            f"— {self.actor} → {self.content_object}: {self.message}"
        )


class DomainMetric(models.Model):
    """
    Stores time-series metrics for each domain.

    Data sources:
    - CPU/Memory: Kubernetes metrics-server API
    - HTTP metrics: Ingress-nginx logs

    Aggregation periods:
    - '5min': Raw data, kept for 24 hours (288 records/domain)
    - 'hourly': Aggregated, kept for 7 days (168 records/domain)
    - 'daily': Aggregated, kept for 30 days (30 records/domain)
    """
    PERIOD_CHOICES = [
        ('5min', '5 Minutes'),
        ('hourly', 'Hourly'),
        ('daily', 'Daily'),
    ]

    domain = models.ForeignKey(
        Domain,
        on_delete=models.CASCADE,
        related_name='metrics'
    )
    timestamp = models.DateTimeField(db_index=True)
    period = models.CharField(max_length=10, choices=PERIOD_CHOICES, default='5min')

    # CPU/Memory metrics (from metrics-server)
    cpu_millicores = models.IntegerField(
        default=0,
        help_text="CPU usage in millicores"
    )
    cpu_limit_millicores = models.IntegerField(
        default=0,
        help_text="CPU limit in millicores"
    )
    memory_bytes = models.BigIntegerField(
        default=0,
        help_text="Memory usage in bytes"
    )
    memory_limit_bytes = models.BigIntegerField(
        default=0,
        help_text="Memory limit in bytes"
    )

    # HTTP metrics (from ingress-nginx logs)
    http_requests = models.IntegerField(
        default=0,
        help_text="Total HTTP requests in this period"
    )
    http_2xx = models.IntegerField(
        default=0,
        help_text="Successful responses (2xx)"
    )
    http_3xx = models.IntegerField(
        default=0,
        help_text="Redirect responses (3xx)"
    )
    http_4xx = models.IntegerField(
        default=0,
        help_text="Client error responses (4xx)"
    )
    http_5xx = models.IntegerField(
        default=0,
        help_text="Server error responses (5xx)"
    )
    avg_latency_ms = models.FloatField(
        default=0,
        help_text="Average response latency in milliseconds"
    )
    bytes_in = models.BigIntegerField(
        default=0,
        help_text="Bytes received from clients"
    )
    bytes_out = models.BigIntegerField(
        default=0,
        help_text="Bytes sent to clients"
    )

    # Storage metrics (from pod exec + du)
    storage_bytes = models.BigIntegerField(
        null=True,
        default=0,
        help_text="Actual storage usage in bytes"
    )
    storage_limit_bytes = models.BigIntegerField(
        null=True,
        default=0,
        help_text="Storage limit (PVC size) in bytes"
    )

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['domain', 'timestamp']),
            models.Index(fields=['domain', 'period', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.domain.domain_name} @ {self.timestamp:%Y-%m-%d %H:%M} ({self.period})"

    @property
    def cpu_percent(self):
        """CPU usage as percentage of limit."""
        if self.cpu_limit_millicores > 0:
            return round(100 * self.cpu_millicores / self.cpu_limit_millicores, 1)
        return 0

    @property
    def memory_percent(self):
        """Memory usage as percentage of limit."""
        if self.memory_limit_bytes > 0:
            return round(100 * self.memory_bytes / self.memory_limit_bytes, 1)
        return 0

    @property
    def memory_mb(self):
        """Memory usage in MB."""
        return round(self.memory_bytes / (1024 * 1024), 1)

    @property
    def memory_limit_mb(self):
        """Memory limit in MB."""
        return round(self.memory_limit_bytes / (1024 * 1024), 1)

    @property
    def storage_percent(self):
        """Storage usage as percentage of limit."""
        if self.storage_limit_bytes > 0:
            return round(100 * self.storage_bytes / self.storage_limit_bytes, 1)
        return 0

    @property
    def storage_gb(self):
        """Storage usage in GB."""
        return round(self.storage_bytes / (1024 * 1024 * 1024), 2)

    @property
    def storage_limit_gb(self):
        """Storage limit in GB."""
        return round(self.storage_limit_bytes / (1024 * 1024 * 1024), 2)


class SystemHealthStatus(models.Model):
    """Stores periodic health check results for system components."""

    COMPONENT_CHOICES = [
        ('linstor', 'Linstor Storage'),
        ('mail_queue', 'Mail Queue'),
        ('mariadb', 'MariaDB'),
    ]

    STATUS_CHOICES = [
        ('healthy', 'Healthy'),
        ('warning', 'Warning'),
        ('error', 'Error'),
        ('unknown', 'Unknown'),
    ]

    component = models.CharField(max_length=50, choices=COMPONENT_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='unknown')
    message = models.TextField(blank=True)
    details = models.JSONField(default=dict, blank=True)
    checked_at = models.DateTimeField(auto_now=True)
    alert_sent = models.BooleanField(default=False)

    class Meta:
        verbose_name = "System Health Status"
        verbose_name_plural = "System Health Statuses"
        ordering = ['-checked_at']
        indexes = [
            models.Index(fields=['component', '-checked_at']),
        ]

    def __str__(self):
        return f"{self.get_component_display()}: {self.status} @ {self.checked_at:%Y-%m-%d %H:%M}"


class SystemSettings(models.Model):
    """Singleton model for system-wide settings."""

    mail_queue_warning_threshold = models.IntegerField(
        default=50,
        help_text="Warn when mail queue exceeds this count"
    )
    mail_queue_error_threshold = models.IntegerField(
        default=100,
        help_text="Error when mail queue exceeds this count"
    )
    health_check_email_enabled = models.BooleanField(
        default=True,
        help_text="Send email alerts for health issues"
    )

    class Meta:
        verbose_name = "System Settings"
        verbose_name_plural = "System Settings"

    def save(self, *args, **kwargs):
        # Ensure only one instance exists
        self.pk = 1
        super().save(*args, **kwargs)

    @classmethod
    def get_settings(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    def __str__(self):
        return "System Settings"
