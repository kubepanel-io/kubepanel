from django import forms
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import make_password
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from dashboard.models import (
    Package, UserProfile, Domain, DomainAlias,
    CloudflareAPIToken, DNSRecord, DNSZone, MailUser, MailAlias,
    WorkloadType, WorkloadVersion,
)
from passlib.hash import sha512_crypt


# Timezone choices for domain containers
TIMEZONE_CHOICES = [
    ('UTC', 'UTC'),
    # Europe
    ('Europe/London', 'Europe/London (GMT/BST)'),
    ('Europe/Lisbon', 'Europe/Lisbon (WET/WEST)'),
    ('Europe/Paris', 'Europe/Paris (CET/CEST)'),
    ('Europe/Berlin', 'Europe/Berlin (CET/CEST)'),
    ('Europe/Budapest', 'Europe/Budapest (CET/CEST)'),
    ('Europe/Bucharest', 'Europe/Bucharest (EET/EEST)'),
    ('Europe/Helsinki', 'Europe/Helsinki (EET/EEST)'),
    ('Europe/Moscow', 'Europe/Moscow (MSK)'),
    # Americas - US
    ('America/New_York', 'America/New_York (EST/EDT)'),
    ('America/Chicago', 'America/Chicago (CST/CDT)'),
    ('America/Denver', 'America/Denver (MST/MDT)'),
    ('America/Los_Angeles', 'America/Los_Angeles (PST/PDT)'),
    ('America/Anchorage', 'America/Anchorage (AKST/AKDT)'),
    ('Pacific/Honolulu', 'Pacific/Honolulu (HST)'),
    # Americas - South America
    ('America/Sao_Paulo', 'America/Sao_Paulo (BRT)'),
    ('America/Buenos_Aires', 'America/Buenos_Aires (ART)'),
    ('America/Lima', 'America/Lima (PET)'),
    ('America/Santiago', 'America/Santiago (CLT/CLST)'),
    ('America/Bogota', 'America/Bogota (COT)'),
    # Asia
    ('Asia/Tokyo', 'Asia/Tokyo (JST)'),
    ('Asia/Shanghai', 'Asia/Shanghai (CST)'),
    ('Asia/Singapore', 'Asia/Singapore (SGT)'),
    ('Asia/Ho_Chi_Minh', 'Asia/Ho_Chi_Minh (ICT)'),
    ('Asia/Bangkok', 'Asia/Bangkok (ICT)'),
    ('Asia/Dubai', 'Asia/Dubai (GST)'),
    ('Asia/Kolkata', 'Asia/Kolkata (IST)'),
    # Australia
    ('Australia/Sydney', 'Australia/Sydney (AEST/AEDT)'),
    ('Australia/Perth', 'Australia/Perth (AWST)'),
    ('Australia/Brisbane', 'Australia/Brisbane (AEST)'),
]


class WorkloadVersionChoiceField(forms.ModelChoiceField):
    """Custom field that displays workload type + version."""
    def label_from_instance(self, obj):
        return f"{obj.workload_type.name} {obj.version}"


class DomainForm(forms.ModelForm):
    """
    Form for Django-backed domain fields (resource limits, workload version).

    These fields are stored in Django for quota enforcement.
    Infrastructure config (app/nginx settings) is in DomainConfigForm.
    """
    workload_version = WorkloadVersionChoiceField(
        queryset=WorkloadVersion.objects.filter(is_active=True).select_related('workload_type'),
        widget=forms.Select(attrs={'class': 'form-select'}),
        label='Workload Version',
        required=True,
    )

    class Meta:
        model = Domain
        fields = ["cpu_limit", "mem_limit", "storage_size", "workload_version"]
        widgets = {
            'cpu_limit': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'CPU Limit in milliCPU',
                'min': 100,
                'max': 4000,
            }),
            'mem_limit': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': 32,
                'max': 4096,
                'placeholder': 'Memory Limit in MiB'
            }),
            'storage_size': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': 1,
                'max': 10000,
                'placeholder': 'Storage in GB'
            }),
        }

    def clean_storage_size(self):
        """Validate that storage size can only be increased, not decreased."""
        new_size = self.cleaned_data.get('storage_size')
        if self.instance and self.instance.pk:
            # Get the original value from the database (not the form)
            from dashboard.models import Domain
            try:
                original = Domain.objects.get(pk=self.instance.pk)
                current_size = original.storage_size
                if new_size < current_size:
                    raise ValidationError(
                        f"Storage size can only be increased. Current: {current_size}GB"
                    )
            except Domain.DoesNotExist:
                pass
        return new_size


class DomainConfigForm(forms.Form):
    """
    Form for domain infrastructure config (workload/nginx settings).

    This is NOT a ModelForm - config is stored in the Kubernetes Domain CR,
    not in the Django database. The CR is the single source of truth.

    Note: PHP-specific fields are shown/hidden via JavaScript based on workload type.
    """
    # General settings
    timezone = forms.ChoiceField(
        choices=TIMEZONE_CHOICES,
        initial='UTC',
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label='Timezone',
        help_text='Timezone for all containers (app, nginx, sftp)',
    )

    # PHP settings (shown only for PHP workloads)
    php_memory_limit = forms.CharField(
        max_length=10,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'e.g. 256M'
        }),
        label='PHP Memory Limit',
    )
    php_max_execution_time = forms.IntegerField(
        min_value=1,
        max_value=300,
        required=False,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': 1,
            'max': 300,
            'placeholder': 'Seconds (1-300)'
        }),
        label='Max Execution Time',
    )
    php_upload_max_filesize = forms.CharField(
        max_length=10,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'e.g. 64M'
        }),
        label='Upload Max Filesize',
    )
    php_post_max_size = forms.CharField(
        max_length=10,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'e.g. 64M'
        }),
        label='Post Max Size',
    )

    # PHP-FPM Pool settings
    fpm_max_children = forms.IntegerField(
        min_value=1,
        max_value=100,
        required=False,
        initial=25,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': 1,
            'max': 100,
            'placeholder': '25'
        }),
        label='FPM Max Children',
        help_text='Maximum number of PHP-FPM worker processes (1-100)',
    )
    fpm_process_idle_timeout = forms.IntegerField(
        min_value=1,
        max_value=300,
        required=False,
        initial=30,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': 1,
            'max': 300,
            'placeholder': '30'
        }),
        label='FPM Idle Timeout',
        help_text='Seconds to wait before killing an idle worker (1-300)',
    )

    # Generic workload custom config (works for all types)
    custom_app_config = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control font-mono',
            'rows': 4,
            'placeholder': '# Custom app configuration'
        }),
        label='Custom App Config',
    )

    # Webserver settings
    document_root = forms.CharField(
        max_length=255,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': '/usr/share/nginx/html/'
        }),
        label='Document Root',
    )
    client_max_body_size = forms.CharField(
        max_length=10,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'e.g. 64m'
        }),
        label='Client Max Body Size',
    )
    ssl_redirect = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label='Redirect HTTP to HTTPS',
    )
    www_redirect = forms.ChoiceField(
        choices=[
            ('none', 'No redirect'),
            ('www-to-root', 'Redirect www to root'),
            ('root-to-www', 'Redirect root to www'),
        ],
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label='WWW Redirect',
    )
    custom_nginx_config = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control font-mono',
            'rows': 4,
            'placeholder': '# Custom nginx location directives\n# location /api { proxy_pass http://...; }'
        }),
        label='Custom Nginx Config',
    )

    # Nginx FastCGI Cache settings
    cache_enabled = forms.BooleanField(
        required=False,
        initial=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label='Enable Page Caching',
    )
    cache_size = forms.ChoiceField(
        choices=[
            ('256Mi', '256 MB'),
            ('512Mi', '512 MB'),
            ('1Gi', '1 GB'),
            ('2Gi', '2 GB'),
        ],
        initial='512Mi',
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label='Cache Size',
    )
    cache_inactive_time = forms.ChoiceField(
        choices=[
            ('30m', '30 minutes'),
            ('60m', '1 hour'),
            ('6h', '6 hours'),
            ('24h', '24 hours'),
        ],
        initial='60m',
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label='Inactive Timeout',
    )
    cache_valid_time = forms.ChoiceField(
        choices=[
            ('5m', '5 minutes'),
            ('10m', '10 minutes'),
            ('30m', '30 minutes'),
            ('1h', '1 hour'),
            ('6h', '6 hours'),
        ],
        initial='10m',
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label='Cache Duration',
    )
    cache_bypass_uris = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control font-mono',
            'rows': 3,
            'placeholder': '/api/\n/webhook/\n/cron/'
        }),
        label='Additional Bypass URIs',
        help_text='One URI pattern per line. WordPress admin, login, and WooCommerce pages are excluded automatically.',
    )

    def to_cr_patch(self, workload_type: str = 'php') -> dict:
        """Convert form data to Domain CR patch format."""
        data = self.cleaned_data
        patch = {
            "workload": {
                "settings": {}
            },
            "webserver": {}
        }

        # Timezone (applies to all containers)
        if data.get("timezone"):
            patch["timezone"] = data["timezone"]

        # Workload settings (PHP-specific settings go in settings dict)
        if workload_type == 'php':
            if data.get("php_memory_limit"):
                patch["workload"]["settings"]["memoryLimit"] = data["php_memory_limit"]
            if data.get("php_max_execution_time"):
                patch["workload"]["settings"]["maxExecutionTime"] = data["php_max_execution_time"]
            if data.get("php_upload_max_filesize"):
                patch["workload"]["settings"]["uploadMaxFilesize"] = data["php_upload_max_filesize"]
            if data.get("php_post_max_size"):
                patch["workload"]["settings"]["postMaxSize"] = data["php_post_max_size"]
            # PHP-FPM pool settings
            if data.get("fpm_max_children"):
                patch["workload"]["settings"]["fpmMaxChildren"] = data["fpm_max_children"]
            if data.get("fpm_process_idle_timeout"):
                patch["workload"]["settings"]["fpmProcessIdleTimeout"] = data["fpm_process_idle_timeout"]

        # Custom config for any workload type
        if data.get("custom_app_config"):
            patch["workload"]["customConfig"] = data["custom_app_config"]

        # Webserver settings
        if data.get("document_root"):
            patch["webserver"]["documentRoot"] = data["document_root"]
        if data.get("client_max_body_size"):
            patch["webserver"]["clientMaxBodySize"] = data["client_max_body_size"]
        patch["webserver"]["sslRedirect"] = data.get("ssl_redirect", True)
        if data.get("www_redirect"):
            patch["webserver"]["wwwRedirect"] = data["www_redirect"]
        if data.get("custom_nginx_config"):
            patch["webserver"]["customConfig"] = data["custom_nginx_config"]

        # Cache settings
        cache = {
            "enabled": data.get("cache_enabled", False),
        }
        if data.get("cache_enabled"):
            cache["size"] = data.get("cache_size", "512Mi")
            cache["inactiveTime"] = data.get("cache_inactive_time", "60m")
            cache["validTime"] = data.get("cache_valid_time", "10m")
            # Convert newline-separated string to list
            bypass_uris_str = data.get("cache_bypass_uris", "")
            if bypass_uris_str:
                cache["bypassUris"] = [
                    uri.strip() for uri in bypass_uris_str.split("\n")
                    if uri.strip()
                ]
        patch["webserver"]["cache"] = cache

        # Clean up empty nested dicts
        if not patch["workload"]["settings"]:
            del patch["workload"]["settings"]
        if not patch["workload"]:
            del patch["workload"]
        if not patch["webserver"]:
            del patch["webserver"]

        return patch

class DomainAddForm(forms.ModelForm):
    """Form for creating a new domain with workload selection."""

    workload_version = WorkloadVersionChoiceField(
        queryset=WorkloadVersion.objects.filter(is_active=True).select_related('workload_type'),
        widget=forms.Select(attrs={'class': 'form-select', 'id': 'id_workload_version'}),
        label='Workload Version',
        required=True,
    )

    timezone = forms.ChoiceField(
        choices=TIMEZONE_CHOICES,
        initial='UTC',
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label='Timezone',
        help_text='Timezone for all containers (app, nginx, sftp)',
    )

    class Meta:
        model = Domain
        fields = ["cpu_limit", "mem_limit", "storage_size", "workload_version"]
        widgets = {
            'cpu_limit': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'CPU Limit in milliCPU',
                'min': 100,
                'max': 4000,
            }),
            'mem_limit': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'Memory Limit in MiB',
                'min': 32,
                'max': 4096,
            }),
            'storage_size': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'Storage size in GiB',
                'min': 1,
                'max': 10000,
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Set default workload version if there's one marked as default
        default_version = WorkloadVersion.objects.filter(is_default=True, is_active=True).first()
        if default_version:
            self.fields['workload_version'].initial = default_version

class APITokenForm(forms.ModelForm):
    class Meta:
        model = CloudflareAPIToken
        fields = ["name", "api_token"]

class ZoneCreationForm(forms.Form):
    zone_name = forms.CharField(max_length=255)
    token = forms.ModelChoiceField(queryset=CloudflareAPIToken.objects.none())

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["token"].queryset = CloudflareAPIToken.objects.filter(user=user)

#  def __init__(self, *args, **kwargs):
#      super().__init__(*args, **kwargs)
#      # Mark scp_port as disabled (rendered as read-only)
#      self.fields['scp_port'].disabled = True

class DNSRecordForm(forms.ModelForm):
    class Meta:
        model = DNSRecord
        fields = ["zone", "record_type", "name", "content", "ttl", "proxied", "priority"]

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        if user:
            self.fields["zone"].queryset = DNSZone.objects.filter(token__user=user)

        # Make priority optional
        self.fields['priority'].required = False

class MailUserForm(forms.ModelForm):
    plain_password = forms.CharField(
        max_length=128,
        widget=forms.PasswordInput(),
        required=True,
        label="Password",
    )

    # Unified domain selection: primary domains + email-enabled aliases
    mail_domain = forms.ChoiceField(
        label="Domain",
        widget=forms.Select(attrs={'class': 'form-select'}),
    )

    class Meta:
        model = MailUser
        fields = ['local_part', 'plain_password', 'active']

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user  # Store for use in clean()
        self.fields['local_part'].widget.attrs.update({'class': 'form-control'})
        self.fields['plain_password'].widget.attrs.update({'class': 'form-control'})
        self.fields['active'].widget.attrs.update({'class': 'form-check-input'})

        # Build choices: primary domains + email-enabled aliases
        if user is not None and not user.is_superuser:
            domains = Domain.objects.filter(owner=user)
        else:
            domains = Domain.objects.all()

        choices = []
        for d in domains:
            choices.append((f"domain:{d.pk}", d.domain_name))
            for alias in d.aliases.filter(email_enabled=True):
                choices.append((f"alias:{alias.pk}", f"{alias.alias_name} (alias of {d.domain_name})"))

        self.fields['mail_domain'].choices = choices

        # For edit mode, set initial value
        if self.instance and self.instance.pk:
            if self.instance.domain_alias:
                self.fields['mail_domain'].initial = f"alias:{self.instance.domain_alias.pk}"
            else:
                self.fields['mail_domain'].initial = f"domain:{self.instance.domain.pk}"

    def clean_mail_domain(self):
        value = self.cleaned_data['mail_domain']
        if ':' not in value:
            raise ValidationError("Invalid selection.")
        kind, pk_str = value.split(':', 1)
        if kind == 'domain':
            try:
                return ('domain', Domain.objects.get(pk=int(pk_str)))
            except (Domain.DoesNotExist, ValueError):
                raise ValidationError("Invalid domain selected.")
        elif kind == 'alias':
            try:
                alias = DomainAlias.objects.select_related('domain').get(pk=int(pk_str))
                if not alias.email_enabled:
                    raise ValidationError("Email is not enabled for this alias domain.")
                return ('alias', alias)
            except (DomainAlias.DoesNotExist, ValueError):
                raise ValidationError("Invalid alias selected.")
        raise ValidationError("Invalid selection.")

    def clean(self):
        cleaned_data = super().clean()

        # Skip limit check for superusers
        if self.user and self.user.is_superuser:
            return cleaned_data

        # Skip if editing existing mail user (not creating new)
        if self.instance and self.instance.pk:
            return cleaned_data

        # Check mail user limit
        if self.user:
            pkg = getattr(self.user.profile, 'package', None)
            if pkg and pkg.max_mail_users is not None:
                current_count = MailUser.objects.filter(domain__owner=self.user).count()
                if current_count >= pkg.max_mail_users:
                    raise ValidationError(
                        f"Mail user limit reached ({current_count}/{pkg.max_mail_users}). "
                        f"Your package allows a maximum of {pkg.max_mail_users} mail users."
                    )

        return cleaned_data

    def save(self, commit=True):
        instance = super().save(commit=False)
        hashed = sha512_crypt.using(rounds=5000).hash(self.cleaned_data['plain_password'])
        instance.password = hashed

        kind, obj = self.cleaned_data['mail_domain']
        if kind == 'domain':
            instance.domain = obj
            instance.domain_alias = None
        else:  # alias
            instance.domain = obj.domain  # FK to parent domain
            instance.domain_alias = obj

        if commit:
            instance.save()
        return instance

class MailAliasForm(forms.ModelForm):
    # Custom choice field to show both domains and email-enabled domain aliases
    mail_domain = forms.ChoiceField(
        label="Domain",
        widget=forms.Select(attrs={'class': 'form-select'}),
    )

    class Meta:
        model = MailAlias
        fields = ['source', 'destination', 'active']  # domain is set via mail_domain
        widgets = {
            'source': forms.TextInput(attrs={'placeholder': 'alias@example.com'}),
            'destination': forms.TextInput(attrs={'placeholder': 'user@example.com'}),
        }

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user

        # Build choices: primary domains + email-enabled domain aliases
        if user is not None and not user.is_superuser:
            domains = Domain.objects.filter(owner=user)
        else:
            domains = Domain.objects.all()

        choices = []
        for d in domains:
            choices.append((f"domain:{d.pk}", d.domain_name))
            for alias in d.aliases.filter(email_enabled=True):
                choices.append((f"alias:{alias.pk}:{d.pk}", f"{alias.alias_name} (alias of {d.domain_name})"))

        self.fields['mail_domain'].choices = choices

        # For edit mode, set initial value based on instance domain
        if self.instance and self.instance.pk:
            self.fields['mail_domain'].initial = f"domain:{self.instance.domain.pk}"

    def clean_mail_domain(self):
        """Validate and parse domain selection."""
        value = self.cleaned_data['mail_domain']
        if ':' not in value:
            raise ValidationError("Invalid selection.")

        parts = value.split(':')
        kind = parts[0]

        if kind == 'domain':
            try:
                domain = Domain.objects.get(pk=int(parts[1]))
                return ('domain', domain, domain.domain_name)
            except (Domain.DoesNotExist, ValueError):
                raise ValidationError("Invalid domain selected.")
        elif kind == 'alias':
            try:
                alias = DomainAlias.objects.get(pk=int(parts[1]))
                parent_domain = Domain.objects.get(pk=int(parts[2]))
                if not alias.email_enabled:
                    raise ValidationError("Email is not enabled for this alias domain.")
                return ('alias', parent_domain, alias.alias_name)
            except (DomainAlias.DoesNotExist, Domain.DoesNotExist, ValueError):
                raise ValidationError("Invalid alias selected.")

        raise ValidationError("Invalid selection.")

    def clean_source(self):
        """Validate source email matches selected domain and user owns it."""
        src = self.cleaned_data.get('source', '').strip()
        if '@' not in src:
            raise ValidationError("Enter a valid email address for the alias source.")

        local, domain_part = src.rsplit('@', 1)

        # Always validate user owns the source domain (security check)
        if self.user and not self.user.is_superuser:
            user_domains = Domain.objects.filter(owner=self.user)
            allowed_domains = set()
            for d in user_domains:
                allowed_domains.add(d.domain_name.lower())
                for alias in d.aliases.filter(email_enabled=True):
                    allowed_domains.add(alias.alias_name.lower())

            if domain_part.lower() not in allowed_domains:
                raise ValidationError(
                    "Source email must be on a domain you own."
                )

        # Also validate source matches the selected mail_domain (if available)
        mail_domain = self.cleaned_data.get('mail_domain')
        if mail_domain:
            kind, parent_domain, domain_name = mail_domain

            # Validate domain part matches selection
            if domain_part.lower() != domain_name.lower():
                raise ValidationError(
                    f"The domain part of the alias must match the selected domain ({domain_name})."
                )

        return src

    def clean_destination(self):
        """Validate destination email is owned by the user."""
        dest = self.cleaned_data.get('destination', '').strip()
        if '@' not in dest:
            raise ValidationError("Enter a valid email address for the destination.")

        local_part, domain_part = dest.rsplit('@', 1)

        # Superusers can use any destination
        if self.user and self.user.is_superuser:
            return dest

        # Check if destination domain is owned by user and find matching MailUser
        user_domains = Domain.objects.filter(owner=self.user)

        # Check primary domains
        for d in user_domains:
            if d.domain_name.lower() == domain_part.lower():
                # Found matching domain, check for MailUser
                if MailUser.objects.filter(
                    local_part__iexact=local_part,
                    domain=d,
                    domain_alias__isnull=True
                ).exists():
                    return dest
                raise ValidationError(
                    "Destination must be an existing email account on your domain."
                )

            # Check domain aliases
            for alias in d.aliases.all():
                if alias.alias_name.lower() == domain_part.lower():
                    # Found matching alias, check for MailUser on this alias
                    if MailUser.objects.filter(
                        local_part__iexact=local_part,
                        domain=d,
                        domain_alias=alias
                    ).exists():
                        return dest
                    raise ValidationError(
                        "Destination must be an existing email account on your domain."
                    )

        raise ValidationError(
            "Destination email must be on a domain you own."
        )

    def save(self, commit=True):
        instance = super().save(commit=False)

        # Set domain FK to parent domain
        kind, parent_domain, domain_name = self.cleaned_data['mail_domain']
        instance.domain = parent_domain

        if commit:
            instance.save()
        return instance

class DomainAliasForm(forms.ModelForm):
    class Meta:
        model = DomainAlias
        fields = ['alias_name']
        widgets = {
            'alias_name': forms.TextInput(attrs={'placeholder': 'e.g. sample.com'}),
        }

class PackageForm(forms.ModelForm):
    class Meta:
        model = Package
        fields = ['name', 'max_storage_size', 'max_cpu', 'max_memory',
                  'max_mail_users', 'max_mail_aliases', 'max_domain_aliases', 'max_domains']
        widgets = {field: forms.NumberInput(attrs={'class':'form-control'})
                   for field in ['max_storage_size','max_cpu','max_memory',
                                 'max_mail_users','max_mail_aliases','max_domain_aliases', 'max_domains']}
        widgets['name'] = forms.TextInput(attrs={'class':'form-control'})

class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['user', 'package']
        widgets = {
            'user': forms.Select(attrs={'class':'form-select'}),
            'package': forms.Select(attrs={'class':'form-select'}),
        }

class UserProfilePackageForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['package']
        widgets = {
            'package': forms.Select(attrs={'class': 'form-select'})
        }

class UserForm(UserCreationForm):
    email = forms.EmailField(
        required=False,
        widget=forms.EmailInput(attrs={'class':'form-control'})
    )
    password1 = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={'class':'form-control'})
    )
    password2 = forms.CharField(
        label="Confirm Password",
        widget=forms.PasswordInput(attrs={'class':'form-control'})
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']
        widgets = {
            'username': forms.TextInput(attrs={'class':'form-control'}),
        }

class PasswordChangeForm(forms.Form):
    new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500',
            'placeholder': 'Enter new password',
            'minlength': '8'
        }),
        min_length=8,
        required=True,
        label='New Password'
    )
    
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500',
            'placeholder': 'Confirm new password',
            'minlength': '8'
        }),
        min_length=8,
        required=True,
        label='Confirm Password'
    )
    
    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')

        if new_password and confirm_password:
            if new_password != confirm_password:
                raise forms.ValidationError('Passwords do not match.')

        return cleaned_data


# =============================================================================
# 2FA Forms
# =============================================================================

class TOTPVerifyForm(forms.Form):
    """Form for entering TOTP code during login verification."""
    code = forms.CharField(
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={
            'class': 'input-focus w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 text-center text-2xl tracking-widest font-mono',
            'placeholder': '000000',
            'autocomplete': 'one-time-code',
            'inputmode': 'numeric',
            'pattern': '[0-9]*',
            'maxlength': '6',
        }),
        label='Authentication Code',
        help_text='Enter the 6-digit code from your authenticator app',
    )

    def clean_code(self):
        code = self.cleaned_data.get('code', '').strip()
        if not code.isdigit():
            raise ValidationError('Code must contain only digits.')
        return code


class TOTPSetupConfirmForm(forms.Form):
    """Form for confirming TOTP setup with initial code verification."""
    code = forms.CharField(
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={
            'class': 'input-focus w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 text-center text-2xl tracking-widest font-mono',
            'placeholder': '000000',
            'autocomplete': 'one-time-code',
            'inputmode': 'numeric',
            'pattern': '[0-9]*',
            'maxlength': '6',
        }),
        label='Verification Code',
        help_text='Enter the code shown in your authenticator app to confirm setup',
    )

    def clean_code(self):
        code = self.cleaned_data.get('code', '').strip()
        if not code.isdigit():
            raise ValidationError('Code must contain only digits.')
        return code


class RecoveryCodeForm(forms.Form):
    """Form for entering a recovery/backup code as alternative to TOTP."""
    code = forms.CharField(
        max_length=16,
        widget=forms.TextInput(attrs={
            'class': 'input-focus w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 text-center tracking-widest font-mono',
            'placeholder': 'XXXX-XXXX',
            'autocomplete': 'off',
        }),
        label='Recovery Code',
        help_text='Enter one of your backup recovery codes',
    )

    def clean_code(self):
        code = self.cleaned_data.get('code', '').strip().upper()
        # Remove any dashes/spaces for normalization
        code = code.replace('-', '').replace(' ', '')
        if not code.isalnum():
            raise ValidationError('Invalid recovery code format.')
        return code


class TOTPDisableForm(forms.Form):
    """Form for disabling 2FA (requires current TOTP code for security)."""
    code = forms.CharField(
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={
            'class': 'input-focus w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent transition-all duration-200 text-center text-2xl tracking-widest font-mono',
            'placeholder': '000000',
            'autocomplete': 'one-time-code',
            'inputmode': 'numeric',
            'pattern': '[0-9]*',
            'maxlength': '6',
        }),
        label='Current Authentication Code',
        help_text='Enter your current TOTP code to disable 2FA',
    )

    def clean_code(self):
        code = self.cleaned_data.get('code', '').strip()
        if not code.isdigit():
            raise ValidationError('Code must contain only digits.')
        return code
