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
    blocked_objects,
    block_entry,
    firewall_rule_delete,
    generate_modsec_rule,
    render_modsec_rules,
)

# Monitoring views
from .monitoring import (
    livetraffic,
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
    'blocked_objects',
    'block_entry',
    'firewall_rule_delete',
    'generate_modsec_rule',
    'render_modsec_rules',

    # Monitoring
    'livetraffic',

    # Utils
    'SuperuserRequiredMixin',
    'random_string',
    'get_country_info',
    'is_static_file',
    'get_client_ip',
    'get_user_agent',
    '_load_k8s_auth',
]
