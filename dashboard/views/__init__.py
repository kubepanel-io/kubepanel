"""
Dashboard views package

Re-exports all views for backwards compatibility with existing imports.
"""

# Auth views
from .auth import (
    kplogin,
    logout_view,
)

# Domain views
from .domains import (
    kpmain,
    add_domain,
    view_domain,
    save_domain,
    delete_domain,
    startstop_domain,
    volumesnapshots,
    restore_backup,
    start_backup,
    domain_logs,
    settings,
    change_password,
    validate_package_limits,
    get_mariadb_root_password,
    update_mariadb_user_password,
    user_can_change_password,
    alias_list,
    alias_add,
    alias_delete,
)

# Mail views
from .mail import (
    list_mail_users,
    create_mail_user,
    edit_mail_user,
    delete_mail_user,
    mail_alias_list,
    mail_alias_create,
    mail_alias_edit,
    mail_alias_delete,
)

# DNS views
from .dns import (
    zones_list,
    create_zone,
    delete_zone,
    list_dns_records,
    create_dns_record,
    edit_dns_record,
    delete_dns_record,
    bulk_delete_dns_records,
    add_api_token,
    list_api_tokens,
    delete_api_token,
    create_dns_record_in_cloudflare,
    create_cf_zone,
    edit_dns_record_simple,
    # Domain-centric DNS views
    domain_dns_records,
    add_domain_dns_record,
    edit_domain_dns_record,
    delete_domain_dns_record,
)

# Node views
from .nodes import (
    node_list,
    node_detail,
    node_cordon,
    node_drain,
    node_uncordon,
    pod_logs,
    backup_logs,
    get_pods_status,
)

# Admin views (CBVs)
from .admin import (
    PackageListView,
    PackageCreateView,
    PackageUpdateView,
    UserProfileListView,
    UserProfileCreateView,
    UserProfileUpdateView,
    UserCreateView,
    UserProfilePackageUpdateView,
    DownloadSnapshotView,
    DownloadSqlDumpView,
    UploadRestoreFilesView,
)

# Security views
from .security import (
    manage_ips,
    add_ip,
    delete_ip,
)

# Monitoring views
from .monitoring import (
    livetraffic,
    livetraffic_api,
    user_livetraffic,
    user_livetraffic_api,
)

# GlobalWAF views
from .global_waf import (
    global_waf_list,
    global_waf_toggle,
    global_waf_add_rule,
    global_waf_edit_rule,
    global_waf_delete_rule,
    global_waf_toggle_geo,
    global_waf_add_country,
    global_waf_remove_country,
)

# L3 Firewall views
from .l3_firewall import (
    l3_firewall_list,
    l3_firewall_toggle,
    l3_firewall_add_rule,
    l3_firewall_edit_rule,
    l3_firewall_delete_rule,
)

# DomainWAF views
from .domain_waf import (
    domain_waf_list,
    domain_waf_toggle,
    domain_waf_add_rule,
    domain_waf_edit_rule,
    domain_waf_delete_rule,
    domain_waf_toggle_geo,
    domain_waf_add_country,
    domain_waf_remove_country,
)

# Metrics views
from .metrics import (
    domain_metrics_page,
    domain_metrics_api,
    domain_metrics_summary,
    global_metrics_page,
    global_metrics_api,
)

# API views
from .api import (
    get_workload_versions,
    get_workload_types,
)

# Utility exports
from .utils import (
    SuperuserRequiredMixin,
    random_string,
    get_country_info,
    is_static_file,
    get_client_ip,
    get_user_agent,
    _load_k8s_auth,
)

__all__ = [
    # Auth
    'kplogin',
    'logout_view',

    # Domains
    'kpmain',
    'add_domain',
    'view_domain',
    'save_domain',
    'delete_domain',
    'startstop_domain',
    'volumesnapshots',
    'restore_backup',
    'start_backup',
    'domain_logs',
    'settings',
    'change_password',
    'validate_package_limits',
    'get_mariadb_root_password',
    'update_mariadb_user_password',
    'user_can_change_password',
    'alias_list',
    'alias_add',
    'alias_delete',

    # Mail
    'list_mail_users',
    'create_mail_user',
    'edit_mail_user',
    'delete_mail_user',
    'mail_alias_list',
    'mail_alias_create',
    'mail_alias_edit',
    'mail_alias_delete',

    # DNS
    'zones_list',
    'create_zone',
    'delete_zone',
    'list_dns_records',
    'create_dns_record',
    'edit_dns_record',
    'delete_dns_record',
    'bulk_delete_dns_records',
    'add_api_token',
    'list_api_tokens',
    'delete_api_token',
    'create_dns_record_in_cloudflare',
    'create_cf_zone',
    'edit_dns_record_simple',
    # Domain-centric DNS
    'domain_dns_records',
    'add_domain_dns_record',
    'edit_domain_dns_record',
    'delete_domain_dns_record',

    # Nodes
    'node_list',
    'node_detail',
    'node_cordon',
    'node_drain',
    'node_uncordon',
    'pod_logs',
    'backup_logs',
    'get_pods_status',

    # Admin CBVs
    'PackageListView',
    'PackageCreateView',
    'PackageUpdateView',
    'UserProfileListView',
    'UserProfileCreateView',
    'UserProfileUpdateView',
    'UserCreateView',
    'UserProfilePackageUpdateView',
    'DownloadSnapshotView',
    'DownloadSqlDumpView',
    'UploadRestoreFilesView',

    # Security
    'manage_ips',
    'add_ip',
    'delete_ip',

    # Monitoring
    'livetraffic',
    'livetraffic_api',
    'user_livetraffic',
    'user_livetraffic_api',

    # GlobalWAF
    'global_waf_list',
    'global_waf_toggle',
    'global_waf_add_rule',
    'global_waf_edit_rule',
    'global_waf_delete_rule',
    'global_waf_toggle_geo',
    'global_waf_add_country',
    'global_waf_remove_country',

    # L3 Firewall
    'l3_firewall_list',
    'l3_firewall_toggle',
    'l3_firewall_add_rule',
    'l3_firewall_edit_rule',
    'l3_firewall_delete_rule',

    # DomainWAF
    'domain_waf_list',
    'domain_waf_toggle',
    'domain_waf_add_rule',
    'domain_waf_edit_rule',
    'domain_waf_delete_rule',
    'domain_waf_toggle_geo',
    'domain_waf_add_country',
    'domain_waf_remove_country',

    # Metrics
    'domain_metrics_page',
    'domain_metrics_api',
    'domain_metrics_summary',
    'global_metrics_page',
    'global_metrics_api',

    # API
    'get_workload_versions',
    'get_workload_types',

    # Utils
    'SuperuserRequiredMixin',
    'random_string',
    'get_country_info',
    'is_static_file',
    'get_client_ip',
    'get_user_agent',
    '_load_k8s_auth',
]
