from django.contrib import admin
from .models import (
    PhpImage, Package, UserProfile, LogEntry, MailUser, MailAlias,
    ClusterIP, Domain, DomainAlias, DNSRecord, DNSZone, CloudflareAPIToken,
    WorkloadType, WorkloadVersion
)


# === Workload Admin ===

class WorkloadVersionInline(admin.TabularInline):
    """Inline editor for workload versions within WorkloadType admin."""
    model = WorkloadVersion
    extra = 1
    fields = ['version', 'image_url', 'is_active', 'is_default', 'display_order']
    ordering = ['display_order', '-version']


@admin.register(WorkloadType)
class WorkloadTypeAdmin(admin.ModelAdmin):
    """Admin for workload types (PHP, Python, Node.js, etc.)"""
    list_display = ['name', 'slug', 'app_port', 'proxy_mode', 'is_active', 'display_order']
    list_editable = ['is_active', 'display_order']
    list_filter = ['is_active', 'proxy_mode']
    search_fields = ['name', 'slug', 'description']
    prepopulated_fields = {'slug': ('name',)}
    inlines = [WorkloadVersionInline]
    fieldsets = (
        (None, {
            'fields': ('name', 'slug', 'description', 'icon')
        }),
        ('Container Configuration', {
            'fields': ('app_port', 'proxy_mode'),
            'description': 'How the app container runs and connects to nginx'
        }),
        ('Default Resources', {
            'fields': ('default_cpu_limit', 'default_memory_limit'),
            'description': 'Default resource limits for domains using this workload type'
        }),
        ('Display Settings', {
            'fields': ('display_order', 'is_active')
        }),
    )


@admin.register(WorkloadVersion)
class WorkloadVersionAdmin(admin.ModelAdmin):
    """Admin for workload versions (individual versions of each type)."""
    list_display = ['workload_type', 'version', 'image_url', 'is_active', 'is_default']
    list_filter = ['workload_type', 'is_active', 'is_default']
    list_editable = ['is_active', 'is_default']
    search_fields = ['version', 'image_url', 'workload_type__name']
    autocomplete_fields = ['workload_type']
    fieldsets = (
        (None, {
            'fields': ('workload_type', 'version', 'image_url')
        }),
        ('Resource Overrides', {
            'fields': ('default_cpu_limit', 'default_memory_limit'),
            'description': 'Override the workload type defaults (leave blank to use type defaults)',
            'classes': ('collapse',)
        }),
        ('Display Settings', {
            'fields': ('display_order', 'is_active', 'is_default')
        }),
    )


# === Other Model Registrations ===

admin.site.register(Domain)
admin.site.register(DomainAlias)
admin.site.register(DNSRecord)
admin.site.register(DNSZone)
admin.site.register(CloudflareAPIToken)
admin.site.register(ClusterIP)
admin.site.register(MailUser)
admin.site.register(MailAlias)
admin.site.register(LogEntry)
admin.site.register(Package)
admin.site.register(UserProfile)
admin.site.register(PhpImage)  # DEPRECATED: Keep for migration compatibility
