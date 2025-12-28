"""
KubePanel Kubernetes Integration

This module provides Django integration with the KubePanel Kubernetes operator.
"""

from .client import (
    K8sClientError,
    K8sConnectionError,
    K8sNotFoundError,
    K8sConflictError,
    K8sValidationError,
)

from .domain import (
    DomainSpec,
    DomainStatus,
    Domain,
    create_domain,
    get_domain,
    get_domain_by_cr_name,
    get_domain_config,
    get_dns_status,
    add_dns_record,
    update_dns_record,
    delete_dns_record_from_cr,
    list_domains,
    update_domain,
    patch_domain,
    delete_domain,
    suspend_domain,
    unsuspend_domain,
    domain_exists,
)

from .secrets import (
    get_secret_value,
    get_secret_from_ref,
    get_sftp_password,
    get_database_password,
    update_sftp_password,
    update_database_password,
    create_dkim_secret,
)

from .backup import (
    Backup,
    BackupStatus,
    list_backups,
    get_backup,
    create_backup,
    delete_backup,
)

from .restore import (
    Restore,
    RestoreStatus,
    list_restores,
    get_restore,
    create_restore,
    delete_restore,
)

from .firewall import (
    sync_modsecurity_rules,
    get_current_modsecurity_rules,
)

from .dnszone import (
    DNSZone,
    DNSZoneStatus,
    create_dnszone,
    get_dnszone,
    dnszone_exists,
    delete_dnszone,
    patch_dnszone_records,
    add_dns_record as add_dnszone_record,
    update_dns_record as update_dnszone_record,
    delete_dns_record as delete_dnszone_record,
    get_dns_records as get_dnszone_records,
    get_dns_record as get_dnszone_record,
    get_dns_status as get_dnszone_status,
)

__all__ = [
    # Exceptions
    'K8sClientError',
    'K8sConnectionError',
    'K8sNotFoundError',
    'K8sConflictError',
    'K8sValidationError',
    
    # Domain classes
    'DomainSpec',
    'DomainStatus',
    'Domain',
    
    # Domain operations
    'create_domain',
    'get_domain',
    'get_domain_by_cr_name',
    'get_domain_config',
    'get_dns_status',
    'add_dns_record',
    'update_dns_record',
    'delete_dns_record_from_cr',
    'list_domains',
    'update_domain',
    'patch_domain',
    'delete_domain',
    'suspend_domain',
    'unsuspend_domain',
    'domain_exists',
    
    # Secret operations
    'get_secret_value',
    'get_secret_from_ref',
    'get_sftp_password',
    'get_database_password',
    'update_sftp_password',
    'update_database_password',
    'create_dkim_secret',

    # Backup operations
    'Backup',
    'BackupStatus',
    'list_backups',
    'get_backup',
    'create_backup',
    'delete_backup',

    # Restore operations
    'Restore',
    'RestoreStatus',
    'list_restores',
    'get_restore',
    'create_restore',
    'delete_restore',

    # Firewall operations
    'sync_modsecurity_rules',
    'get_current_modsecurity_rules',

    # DNSZone operations
    'DNSZone',
    'DNSZoneStatus',
    'create_dnszone',
    'get_dnszone',
    'dnszone_exists',
    'delete_dnszone',
    'patch_dnszone_records',
    'add_dnszone_record',
    'update_dnszone_record',
    'delete_dnszone_record',
    'get_dnszone_records',
    'get_dnszone_record',
    'get_dnszone_status',
]
