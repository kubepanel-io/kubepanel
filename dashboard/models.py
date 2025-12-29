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
    version = models.CharField(max_length=50, unique=True)
    repository_url = models.CharField(max_length=255)

    def __str__(self):
        return self.repository_url


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
    
    # === PHP Configuration ===
    php_image = models.ForeignKey(
        PhpImage,
        on_delete=models.PROTECT,
        related_name='domains',
        help_text="PHP version for this domain"
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
        
        # Check PHP image
        if self.php_image_id is None:
            raise ValidationError({
                'php_image': 'A PHP version must be selected.'
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
