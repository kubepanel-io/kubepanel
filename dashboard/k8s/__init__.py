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
)

from .backup import (
    Backup,
    BackupStatus,
    list_backups,
    get_backup,
    create_backup,
    delete_backup,
)

from .firewall import (
    sync_modsecurity_rules,
    get_current_modsecurity_rules,
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

    # Backup operations
    'Backup',
    'BackupStatus',
    'list_backups',
    'get_backup',
    'create_backup',
    'delete_backup',

    # Firewall operations
    'sync_modsecurity_rules',
    'get_current_modsecurity_rules',
]
