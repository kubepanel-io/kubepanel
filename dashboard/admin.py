from django.contrib import admin
from .models import PhpImage, Package, UserProfile, LogEntry, MailUser, MailAlias, ClusterIP, Domain, DomainAlias, BlockRule, DNSRecord, DNSZone, CloudflareAPIToken

admin.site.register(Domain)
admin.site.register(DomainAlias)
admin.site.register(BlockRule)
admin.site.register(DNSRecord)
admin.site.register(DNSZone)
admin.site.register(CloudflareAPIToken)
admin.site.register(ClusterIP)
admin.site.register(MailUser)
admin.site.register(MailAlias)
admin.site.register(LogEntry)
admin.site.register(Package)
admin.site.register(UserProfile)
admin.site.register(PhpImage)
