from django import forms
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import make_password
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from dashboard.models import PhpImage, Package, UserProfile, Domain, DomainAlias, CloudflareAPIToken, DNSRecord, DNSZone, MailUser, MailAlias
from passlib.hash import sha512_crypt

class PhpImageChoiceField(forms.ModelChoiceField):
    def label_from_instance(self, obj):
        # return whatever you like here; for example:
        return f"{obj.version}"

class DomainForm(forms.ModelForm):

  php_image = PhpImageChoiceField(
      queryset=PhpImage.objects.all(),
      widget=forms.Select(attrs={'class': 'form-select'}),
      label='PHP Version',
      required=True,
  )

  class Meta:
    model = Domain
    fields = ["cpu_limit","mem_limit", "php_image"]
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
    }

class DomainAddForm(forms.ModelForm):

  php_image = PhpImageChoiceField(
      queryset=PhpImage.objects.all(),
      widget=forms.Select(attrs={'class': 'form-select'}),
      label='PHP Version',
      required=True,
  )

  class Meta:
    model = Domain
    fields = ["cpu_limit","mem_limit","storage_size", "php_image"]
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

    class Meta:
        model = MailUser
        fields = ['domain', 'local_part', 'plain_password', 'active']

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        # add bootstrap classes
        self.fields['domain'].widget.attrs.update({'class': 'form-select'})
        self.fields['local_part'].widget.attrs.update({'class': 'form-control'})
        self.fields['plain_password'].widget.attrs.update({'class': 'form-control'})
        self.fields['active'].widget.attrs.update({'class': 'form-check-input'})
        # if a non-superuser, limit domains
        if user is not None and not user.is_superuser:
            self.fields['domain'].queryset = Domain.objects.filter(owner=user)

    def save(self, commit=True):
        instance = super().save(commit=False)
        hashed = sha512_crypt.using(rounds=5000).hash(self.cleaned_data['plain_password'])
        instance.password = hashed
        if commit:
            instance.save()
        return instance

class MailAliasForm(forms.ModelForm):
    class Meta:
        model = MailAlias
        fields = ['domain', 'source', 'destination', 'active']
        widgets = {
            'source': forms.TextInput(attrs={'placeholder': 'alias@example.com'}),
            'destination': forms.TextInput(attrs={'placeholder': 'user@example.com'}),
        }

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        # limit domains for non-superusers
        if user is not None and not user.is_superuser:
            self.fields['domain'].queryset = Domain.objects.filter(owner=user)

    def clean_source(self):
        src = self.cleaned_data.get('source', '').strip()
        if '@' not in src:
            raise ValidationError("Enter a valid email address for the alias source.")
        local, domain_part = src.rsplit('@', 1)
        domain_obj = self.cleaned_data.get('domain')
        # sanity: must have picked a domain
        if not domain_obj:
            return src

        # check user actually owns this domain
        if not self.user.is_superuser and domain_obj.owner != self.user:
            raise ValidationError("You don’t have permission to make aliases on that domain.")

        # gather allowed hostnames: the real domain + any of its DomainAlias entries
        allowed = { domain_obj.domain_name.lower() }
        allowed |= set(
            DomainAlias.objects
                .filter(domain=domain_obj)
                .values_list('alias_name', flat=True)
        )

        if domain_part.lower() not in allowed:
            raise ValidationError(
                "The domain part of the alias must be one you control (either the domain itself or one of its aliases)."
            )
        return src

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
                  'max_mail_users', 'max_mail_aliases', 'max_domain_aliases']
        widgets = {field: forms.NumberInput(attrs={'class':'form-control'})
                   for field in ['max_storage_size','max_cpu','max_memory',
                                 'max_mail_users','max_mail_aliases','max_domain_aliases']}
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
