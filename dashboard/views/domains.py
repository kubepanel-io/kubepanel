"""
Domain management views (CRUD, backup, credentials, etc.)
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Sum
from django.db import transaction
from django.core.exceptions import ValidationError
from django.contrib.contenttypes.models import ContentType
from kubernetes import client, config

import os
import logging
import base64
import pymysql

from dashboard.models import Domain, DomainAlias, PhpImage, MailUser, CloudflareAPIToken, ClusterIP, LogEntry
from dashboard.forms import DomainForm, DomainAddForm, DomainAliasForm
from dashboard.services.dns_service import DNSZoneManager, CloudflareAPIException, generate_email_dns_records
from dashboard.k8s import (
    DomainSpec,
    create_domain as k8s_create_domain,
    delete_domain as k8s_delete_domain,
    get_domain as k8s_get_domain,
    patch_domain as k8s_patch_domain,
    suspend_domain as k8s_suspend_domain,
    unsuspend_domain as k8s_unsuspend_domain,
    get_sftp_password,
    get_database_password,
    get_secret_value,
    update_sftp_password as k8s_update_sftp_password,
    update_database_password as k8s_update_database_password,
    K8sClientError,
    K8sConflictError,
    K8sNotFoundError,
    list_backups,
    create_backup as k8s_create_backup,
    get_backup,
    create_restore,
    list_restores,
)

logger = logging.getLogger("django")


@login_required(login_url="/dashboard/")
def kpmain(request):
    """Main dashboard view"""
    if request.user.is_superuser:
        domains = list(Domain.objects.all())
    else:
        domains = list(Domain.objects.filter(owner=request.user))

    # Fetch all K8s Domain CRs in one API call and build lookup by domain name
    try:
        from dashboard.k8s import list_domains as k8s_list_domains
        k8s_domains = {d.domain_name: d for d in k8s_list_domains()}
    except Exception as e:
        logger.warning(f"Failed to fetch K8s domains: {e}")
        k8s_domains = {}

    # Annotate each Django domain with K8s status
    for domain in domains:
        k8s_domain = k8s_domains.get(domain.domain_name)
        if k8s_domain and k8s_domain.status:
            domain.k8s_status = k8s_domain.status.phase or 'Unknown'
        else:
            domain.k8s_status = 'NotFound'

    pkg = getattr(request.user.profile, 'package', None)
    totals = Domain.objects.filter(
        pk__in=[d.pk for d in domains]
    ).aggregate(
        total_storage=Sum('storage_size'),
        total_cpu=Sum('cpu_limit'),
        total_mem=Sum('mem_limit'),
    )
    total_storage = totals['total_storage'] or 0
    total_cpu = totals['total_cpu'] or 0
    total_mem = totals['total_mem'] or 0
    total_mail_users = MailUser.objects.filter(domain__owner=request.user).count()
    total_domain_aliases = sum(d.aliases.count() for d in domains)

    return render(request, 'main/domain.html', {
        'domains': domains,
        'pkg': pkg,
        'total_storage': total_storage,
        'total_cpu': total_cpu,
        'total_mem': total_mem,
        'total_mail_users': total_mail_users,
        'total_domain_aliases': total_domain_aliases,
    })


@login_required(login_url="/dashboard/")
def add_domain(request):
    """
    Add a new domain.
    Uses atomic transaction to ensure consistency.
    """
    if request.method == 'POST':
        try:
            # Extract form data
            domain_name = request.POST.get("domain_name", "").strip()[:253]
            mem_limit = int(request.POST.get("mem_limit", 256))
            cpu_limit = int(request.POST.get("cpu_limit", 500))
            storage_size = int(request.POST.get("storage_size", 5))
            php_image_id = request.POST.get("php_image", "")

            if not domain_name:
                messages.error(request, "Domain name is required.")
                return redirect('add_domain')

            try:
                php_image = PhpImage.objects.get(pk=int(php_image_id))
            except (PhpImage.DoesNotExist, ValueError):
                messages.error(request, "Invalid PHP version selected.")
                return redirect('add_domain')

            if Domain.objects.filter(domain_name=domain_name).exists():
                messages.error(request, f"Domain '{domain_name}' already exists.")
                return redirect('add_domain')

            wp_preinstall = request.POST.get("wordpress_preinstall") == "1"
            auto_dns = request.POST.get("auto_dns") == "1"
            api_token = request.POST.get("api_token", "") if auto_dns else None

            # Build Domain CR spec
            domain_spec = DomainSpec(
                domain_name=domain_name,
                php_version=php_image.version,
                storage=f"{storage_size}Gi",
                cpu_limit=f"{cpu_limit}m",
                memory_limit=f"{mem_limit}Mi",
            )
            domain_spec.title = domain_name
            domain_spec.wordpress_preinstall = wp_preinstall
            domain_spec.email_enabled = True

            # Build Django model (don't save yet)
            domain_model = Domain(
                owner=request.user,
                domain_name=domain_name,
                title=domain_name,
                php_image=php_image,
                storage_size=storage_size,
                cpu_limit=cpu_limit,
                mem_limit=mem_limit,
            )

            try:
                domain_model.full_clean()
            except ValidationError as e:
                for field, errors in e.message_dict.items():
                    for error in errors:
                        messages.error(request, f"{field}: {error}")
                return redirect('add_domain')

            # Atomic operation: Create both or neither
            k8s_domain = None
            try:
                with transaction.atomic():
                    domain_model.save()

                    try:
                        k8s_domain = k8s_create_domain(
                            spec=domain_spec,
                            owner=request.user.username,
                        )
                        logger.info(f"Created Domain CR '{k8s_domain.name}' for '{domain_name}'")
                    except K8sConflictError:
                        raise ValueError(f"Domain '{domain_name}' already exists in cluster.")
                    except K8sClientError as e:
                        logger.error(f"Failed to create Domain CR: {e}")
                        raise ValueError(f"Failed to create domain in cluster: {str(e)}")

                    LogEntry.objects.create(
                        content_object=domain_model,
                        actor=f"user:{request.user.username}",
                        user=request.user,
                        level="INFO",
                        message=f"Created domain {domain_name}",
                        data={"domain_id": domain_model.pk}
                    )

            except ValueError as e:
                messages.error(request, str(e))
                return redirect('add_domain')
            except Exception as e:
                if k8s_domain:
                    try:
                        k8s_delete_domain(domain_name)
                        logger.info(f"Rolled back Domain CR '{domain_name}'")
                    except K8sClientError:
                        logger.error(f"Failed to rollback Domain CR '{domain_name}'")

                logger.exception(f"Error creating domain: {e}")
                messages.error(request, f"Failed to create domain: {str(e)}")
                return redirect('add_domain')

            # Handle auto DNS if requested
            if auto_dns and api_token:
                try:
                    user_token = CloudflareAPIToken.objects.get(
                        api_token=api_token,
                        user=request.user
                    )
                    cluster_ips = list(ClusterIP.objects.values_list("ip_address", flat=True))
                    dns_records = generate_email_dns_records(domain_name, cluster_ips)
                    zone_manager = DNSZoneManager(user_token)
                    zone_obj, created_records = zone_manager.create_zone_with_records(
                        domain_name,
                        dns_records
                    )

                    logger.info(f"Created DNS zone for '{domain_name}' with {len(created_records)} records")
                    messages.success(
                        request,
                        f"Domain '{domain_name}' created with {len(created_records)} DNS records."
                    )

                except CloudflareAPIToken.DoesNotExist:
                    logger.warning(f"API token not found for DNS setup")
                    messages.warning(
                        request,
                        f"Domain '{domain_name}' created, but DNS setup failed: Invalid API token."
                    )
                except CloudflareAPIException as e:
                    logger.error(f"Cloudflare API error: {e}")
                    messages.warning(
                        request,
                        f"Domain '{domain_name}' created, but DNS setup failed: {e.message}"
                    )
                except Exception as e:
                    logger.error(f"DNS setup error: {e}")
                    messages.warning(
                        request,
                        f"Domain '{domain_name}' created, but DNS setup failed: {str(e)}"
                    )
            else:
                messages.success(request, f"Domain '{domain_name}' created successfully.")

            return redirect('domain_logs', domain=domain_name)

        except Exception as e:
            logger.exception(f"Unexpected error in add_domain: {e}")
            messages.error(request, f"An unexpected error occurred: {str(e)}")
            return redirect('add_domain')

    else:
        tokens = CloudflareAPIToken.objects.filter(user=request.user)
        form = DomainAddForm()
        return render(request, "main/add_domain.html", {
            "form": form,
            "api_tokens": tokens,
        })


@login_required(login_url="/dashboard/")
def view_domain(request, domain):
    """
    View domain details with credentials fetched from Kubernetes.
    """
    try:
        if request.user.is_superuser:
            domain_model = Domain.objects.get(domain_name=domain)
        else:
            domain_model = Domain.objects.get(owner=request.user, domain_name=domain)
        form = DomainForm(instance=domain_model)
    except Domain.DoesNotExist:
        return HttpResponse("Permission denied.")

    k8s_credentials = {
        'sftp_port': None,
        'sftp_username': 'webuser',
        'sftp_password': None,
        'sftp_privkey': None,
        'database_name': None,
        'database_username': None,
        'database_password': None,
        'dkim_pubkey': None,
        'dkim_dns_record': None,
        'phase': 'Unknown',
        'error': None,
    }

    try:
        k8s_domain = k8s_get_domain(domain)
        if k8s_domain:
            status = k8s_domain.status
            k8s_credentials['phase'] = status.phase or 'Unknown'
            k8s_credentials['sftp_port'] = status.sftp_port
            k8s_credentials['sftp_username'] = status.sftp_username or 'webuser'

            try:
                k8s_credentials['sftp_password'] = get_sftp_password(status)
            except Exception as e:
                logger.warning(f"Failed to get SFTP password for {domain}: {e}")

            try:
                k8s_credentials['sftp_privkey'] = get_secret_value(
                    name='sftp-credentials',
                    namespace=domain_model.namespace,
                    key='ssh-privatekey'
                )
            except Exception as e:
                logger.warning(f"Failed to get SFTP private key for {domain}: {e}")

            k8s_credentials['database_name'] = status.database_name
            k8s_credentials['database_username'] = status.database_username

            try:
                k8s_credentials['database_password'] = get_database_password(status)
            except Exception as e:
                logger.warning(f"Failed to get database password for {domain}: {e}")

            k8s_credentials['dkim_pubkey'] = status.dkim_public_key
            k8s_credentials['dkim_dns_record'] = status.dkim_dns_record

    except K8sNotFoundError:
        k8s_credentials['error'] = 'Domain not found in Kubernetes cluster'
        k8s_credentials['phase'] = 'NotFound'
    except K8sClientError as e:
        k8s_credentials['error'] = f'Failed to fetch domain from Kubernetes: {e}'
        k8s_credentials['phase'] = 'Error'
    except Exception as e:
        logger.exception(f"Unexpected error fetching K8s domain {domain}: {e}")
        k8s_credentials['error'] = 'Unexpected error fetching domain status'
        k8s_credentials['phase'] = 'Error'

    return render(request, "main/view_domain.html", {
        "domain": domain_model,
        "form": form,
        "k8s": k8s_credentials,
    })


@login_required(login_url="/dashboard/")
def save_domain(request, domain):
    """Save domain settings. Updates both Django model and K8s Domain CR."""
    try:
        domain_instance = Domain.objects.get(domain_name=domain)
    except Domain.DoesNotExist:
        return HttpResponse("Domain not found", status=404)

    if domain_instance.owner != request.user and not request.user.is_superuser:
        return HttpResponse("Permission denied.")

    if request.method != 'POST':
        return redirect('view_domain', domain=domain_instance.domain_name)

    form = DomainForm(request.POST, instance=domain_instance)
    if not form.is_valid():
        k8s_credentials = {'phase': 'Unknown', 'error': None}
        try:
            k8s_domain = k8s_get_domain(domain)
            if k8s_domain:
                status = k8s_domain.status
                k8s_credentials['phase'] = status.phase or 'Unknown'
                k8s_credentials['sftp_port'] = status.sftp_port
                k8s_credentials['sftp_username'] = status.sftp_username or 'webuser'
                k8s_credentials['sftp_password'] = get_sftp_password(status)
                k8s_credentials['database_name'] = status.database_name
                k8s_credentials['database_username'] = status.database_username
                k8s_credentials['database_password'] = get_database_password(status)
                k8s_credentials['dkim_pubkey'] = status.dkim_public_key
        except Exception:
            pass
        return render(request, "main/view_domain.html", {
            "domain": domain_instance,
            "form": form,
            "k8s": k8s_credentials,
        })

    form.save()

    try:
        patch = {
            "resources": {
                "limits": {
                    "cpu": f"{domain_instance.cpu_limit}m",
                    "memory": f"{domain_instance.mem_limit}Mi",
                }
            },
            "php": {
                "version": domain_instance.php_image.version,
                "settings": {
                    "memoryLimit": domain_instance.php_memory_limit,
                    "maxExecutionTime": domain_instance.php_max_execution_time,
                    "uploadMaxFilesize": domain_instance.php_upload_max_filesize,
                    "postMaxSize": domain_instance.php_post_max_size,
                },
            },
            "webserver": {
                "documentRoot": domain_instance.document_root,
                "clientMaxBodySize": domain_instance.client_max_body_size,
                "sslRedirect": domain_instance.ssl_redirect,
                "wwwRedirect": domain_instance.www_redirect,
            },
        }
        # Add custom configs only if they have content
        if domain_instance.custom_php_config:
            patch["php"]["customConfig"] = domain_instance.custom_php_config
        if domain_instance.custom_nginx_config:
            patch["webserver"]["customConfig"] = domain_instance.custom_nginx_config

        k8s_patch_domain(domain_instance.domain_name, patch)
        logger.info(f"Patched Domain CR for {domain_instance.domain_name}")
    except K8sNotFoundError:
        messages.warning(request, "Domain not found in Kubernetes. Settings saved locally only.")
    except K8sClientError as e:
        logger.error(f"Failed to patch Domain CR for {domain}: {e}")
        messages.warning(request, f"Settings saved locally, but failed to update Kubernetes: {e}")

    LogEntry.objects.create(
        content_object=domain_instance,
        actor=f"user:{request.user.username}",
        user=request.user,
        level="INFO",
        message=f"Settings saved for {domain_instance.domain_name}",
        data={
            "domain_id": domain_instance.pk,
            "cpu_limit": domain_instance.cpu_limit,
            "mem_limit": domain_instance.mem_limit,
            "php_version": domain_instance.php_image.version,
            "php_memory_limit": domain_instance.php_memory_limit,
            "document_root": domain_instance.document_root,
        }
    )

    messages.success(request, "Domain settings saved successfully.")
    return redirect('view_domain', domain=domain_instance.domain_name)


@login_required(login_url="/dashboard/")
def delete_domain(request, domain):
    """Delete a domain."""
    try:
        domain_model = Domain.objects.get(domain_name=domain)
    except Domain.DoesNotExist:
        messages.error(request, f"Domain '{domain}' not found.")
        return redirect('kpmain')

    if domain_model.owner != request.user and not request.user.is_superuser:
        messages.error(request, "You don't have permission to delete this domain.")
        return redirect('kpmain')

    if request.method == 'POST':
        try:
            try:
                k8s_delete_domain(domain)
                logger.info(f"Deleted Domain CR for '{domain}'")
            except K8sNotFoundError:
                logger.warning(f"Domain CR for '{domain}' not found in cluster (may be already deleted)")
            except K8sClientError as e:
                logger.error(f"Failed to delete Domain CR: {e}")
                messages.error(request, f"Failed to delete domain from cluster: {str(e)}")
                return redirect('view_domain', domain=domain)

            LogEntry.objects.create(
                content_object=domain_model,
                actor=f"user:{request.user.username}",
                user=request.user,
                level="INFO",
                message=f"Deleted domain {domain}",
                data={"domain_name": domain}
            )

            domain_model.delete()
            messages.success(request, f"Domain '{domain}' deleted successfully.")
            return redirect('kpmain')

        except Exception as e:
            logger.exception(f"Error deleting domain: {e}")
            messages.error(request, f"Failed to delete domain: {str(e)}")
            return redirect('view_domain', domain=domain)

    return render(request, "main/delete_domain_confirm.html", {
        "domain": domain_model,
    })


@login_required(login_url="/dashboard/")
def startstop_domain(request, domain, action):
    """Start or stop (suspend/unsuspend) a domain."""
    try:
        domain_model = Domain.objects.get(domain_name=domain)
    except Domain.DoesNotExist:
        messages.error(request, f"Domain '{domain}' not found.")
        return redirect('kpmain')

    if domain_model.owner != request.user and not request.user.is_superuser:
        messages.error(request, "You don't have permission to modify this domain.")
        return redirect('kpmain')

    try:
        if action == 'stop':
            k8s_suspend_domain(domain)
            messages.success(request, f"Domain '{domain}' suspended.")

            LogEntry.objects.create(
                content_object=domain_model,
                actor=f"user:{request.user.username}",
                user=request.user,
                level="INFO",
                message=f"Suspended domain {domain}",
            )

        elif action == 'start':
            k8s_unsuspend_domain(domain)
            messages.success(request, f"Domain '{domain}' started.")

            LogEntry.objects.create(
                content_object=domain_model,
                actor=f"user:{request.user.username}",
                user=request.user,
                level="INFO",
                message=f"Started domain {domain}",
            )

        else:
            messages.error(request, f"Invalid action: {action}")

    except K8sNotFoundError:
        messages.error(request, f"Domain '{domain}' not found in cluster.")
    except K8sClientError as e:
        logger.error(f"Failed to {action} domain: {e}")
        messages.error(request, f"Failed to {action} domain: {str(e)}")

    return redirect('view_domain', domain=domain)


@login_required(login_url="/dashboard/")
def volumesnapshots(request, domain):
    """List backups and restores for a domain from Kubernetes CRs."""
    try:
        if request.user.is_superuser:
            domain_obj = Domain.objects.get(domain_name=domain)
        else:
            domain_obj = Domain.objects.get(owner=request.user, domain_name=domain)
    except Domain.DoesNotExist:
        return HttpResponse("Permission denied")

    # Get namespace from domain name
    namespace = f"dom-{domain.replace('.', '-')}"

    # Fetch backups from Kubernetes
    try:
        backups = list_backups(namespace)
    except K8sClientError as e:
        logger.error(f"Failed to list backups for {domain}: {e}")
        backups = []
        messages.error(request, f"Failed to fetch backups: {e}")

    # Fetch restores from Kubernetes
    try:
        restores = list_restores(namespace)
    except K8sClientError as e:
        logger.error(f"Failed to list restores for {domain}: {e}")
        restores = []
        messages.error(request, f"Failed to fetch restores: {e}")

    context = {
        "backups": backups,
        "restores": restores,
        "domain": domain,
    }
    return render(request, "main/volumesnapshot.html", context)


@login_required(login_url="/dashboard/")
def restore_backup(request, domain, backup_name):
    """
    Restore from a backup.

    Creates a Restore CR that triggers the operator to:
    1. Scale down the domain deployment
    2. Restore the VolumeSnapshot to the domain's PVC
    3. Restore the database from the dump file
    4. Scale up the domain deployment
    """
    # Check permissions
    try:
        if request.user.is_superuser:
            domain_obj = Domain.objects.get(domain_name=domain)
        else:
            domain_obj = Domain.objects.get(owner=request.user, domain_name=domain)
    except Domain.DoesNotExist:
        return HttpResponse("Permission denied")

    namespace = f"dom-{domain.replace('.', '-')}"

    # Find the backup that has this volumesnapshot
    try:
        backups = list_backups(namespace)
    except K8sClientError as e:
        logger.error(f"Failed to list backups for {domain}: {e}")
        messages.error(request, f"Failed to fetch backups: {e}")
        return redirect('volumesnapshots', domain=domain)

    # Find the backup by name
    backup = None
    for b in backups:
        if b.name == backup_name:
            backup = b
            break

    if not backup:
        messages.error(request, f"Backup '{backup_name}' not found.")
        return redirect('volumesnapshots', domain=domain)

    # Check that backup is complete
    if backup.status.phase != 'Completed':
        messages.error(request, f"Cannot restore from backup in '{backup.status.phase}' state. Only completed backups can be restored.")
        return redirect('volumesnapshots', domain=domain)

    # Check that we have the required data
    if not backup.status.volume_snapshot_name or not backup.status.database_backup_path:
        messages.error(request, "Backup is missing required data (VolumeSnapshot or database path).")
        return redirect('volumesnapshots', domain=domain)

    if request.method == 'POST':
        # Validate confirmation
        if request.POST.get("imsure") != domain:
            error = "Domain name didn't match"
            return render(request, "main/restore_snapshot.html", {
                "domain": domain,
                "backup_name": backup_name,
                "error": error,
            })

        # Create Restore CR
        try:
            restore = create_restore(
                namespace=namespace,
                domain_name=domain,
                backup_name=backup.name,
                volume_snapshot_name=backup.status.volume_snapshot_name,
                database_backup_path=backup.status.database_backup_path,
            )
            messages.success(request, f"Restore started. The domain will be temporarily unavailable while restoring from backup '{backup.name}'.")
            logger.info(f"Created Restore CR {restore.name} for {domain} from backup {backup.name}")
        except K8sClientError as e:
            logger.error(f"Failed to create restore for {domain}: {e}")
            messages.error(request, f"Failed to start restore: {e}")

        return redirect('volumesnapshots', domain=domain)

    # GET request - show confirmation form
    return render(request, "main/restore_snapshot.html", {
        "domain": domain,
        "backup_name": backup_name,
        "backup": backup,
    })


@login_required(login_url="/dashboard/")
def start_backup(request, domain):
    """Start a manual backup by creating a Backup CR."""
    if request.method == 'POST':
        if request.POST.get("imsure") != domain:
            error = "Domain name didn't match"
            return render(request, "main/start_backup.html", {"domain": domain, "error": error})

        # Check permissions
        if not request.user.is_superuser:
            try:
                domain_obj = Domain.objects.get(owner=request.user, domain_name=domain)
            except Domain.DoesNotExist:
                return HttpResponse("Permission denied.")
        else:
            try:
                domain_obj = Domain.objects.get(domain_name=domain)
            except Domain.DoesNotExist:
                return HttpResponse("Domain not found.")

        # Get namespace from domain name
        namespace = f"dom-{domain.replace('.', '-')}"

        # Create Backup CR
        try:
            backup = k8s_create_backup(
                namespace=namespace,
                domain_name=domain,
                backup_type='manual',
            )
            messages.success(request, f"Backup started: {backup.name}")

            # Log the backup
            LogEntry.objects.create(
                content_object=domain_obj,
                actor=f"user:{request.user.username}",
                user=request.user,
                level="INFO",
                message=f"Manual backup started for {domain}",
                data={"backup_name": backup.name}
            )

            return redirect('volumesnapshots', domain=domain)

        except K8sClientError as e:
            logger.error(f"Failed to create backup for {domain}: {e}")
            messages.error(request, f"Failed to start backup: {e}")
            return render(request, "main/start_backup.html", {"domain": domain, "error": str(e)})

    return render(request, "main/start_backup.html", {"domain": domain})


@login_required(login_url="/dashboard/")
def domain_logs(request, domain):
    domain_obj = get_object_or_404(Domain, domain_name=domain)
    ct = ContentType.objects.get_for_model(Domain)
    logs = (
        LogEntry.objects
        .filter(content_type=ct, object_id=domain_obj.pk)
        .order_by('-timestamp')
    )
    return render(request, 'main/domain_logs.html', {
        'domain': domain_obj.domain_name,
        'logs': logs,
    })


def settings(request):
    return render(request, "main/settings.html")


# Password management functions
def get_mariadb_root_password():
    """Retrieve MariaDB root password from Kubernetes secret"""
    try:
        try:
            config.load_incluster_config()
        except:
            config.load_kube_config()

        v1 = client.CoreV1Api()
        secret = v1.read_namespaced_secret(
            name="mariadb-auth",
            namespace="kubepanel"
        )

        encoded_password = secret.data.get("password")
        if encoded_password:
            return base64.b64decode(encoded_password).decode('utf-8')
        else:
            raise Exception("Password key not found in secret")

    except Exception as e:
        print(f"Error retrieving MariaDB root password: {e}")
        raise


def update_mariadb_user_password(username, new_password):
    """Connect to MariaDB and update user password"""
    try:
        root_password = get_mariadb_root_password()

        connection = pymysql.connect(
            host='mariadb.kubepanel.svc.cluster.local',
            port=3306,
            user='root',
            password=root_password,
            charset='utf8mb4',
            autocommit=True
        )

        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT User, Host FROM mysql.user WHERE User = %s", (username,))
                existing_users = cursor.fetchall()
                logger.info(f"Found existing users for '{username}': {existing_users}")

                if not existing_users:
                    logger.warning(f"No users found with username '{username}'. Cannot update password.")
                    raise Exception(f"Database user '{username}' does not exist")

                success_count = 0
                for user_row in existing_users:
                    user, host = user_row
                    try:
                        cursor.execute("SET PASSWORD FOR %s@%s = PASSWORD(%s)", (user, host, new_password))
                        logger.info(f"Successfully updated password for {user}@{host}")
                        success_count += 1
                    except pymysql.Error as e:
                        logger.error(f"Could not update password for {user}@{host}: {e}")
                        continue

                if success_count == 0:
                    raise Exception(f"Failed to update password for any instances of user '{username}'")

                cursor.execute("FLUSH PRIVILEGES")
                logger.info(f"Successfully updated password for {success_count} instance(s) of database user: {username}")

        finally:
            connection.close()

    except Exception as e:
        logger.error(f"Error updating MariaDB user password: {e}")
        raise


def user_can_change_password(user, domain_obj, password_type):
    """Check if user has permission to change the specified password type for the domain"""
    if user.is_superuser:
        return True, None

    if domain_obj.owner != user:
        return False, "You don't have permission to change passwords for this domain."

    return True, None


def change_password(request, domain, password_type):
    """Handle password changes for database or SFTP passwords."""
    try:
        domain_obj = Domain.objects.get(domain_name=domain)
    except Domain.DoesNotExist:
        return HttpResponse("Domain not found", status=404)

    can_change, error_message = user_can_change_password(request.user, domain_obj, password_type)
    if not can_change:
        return HttpResponse(f"Permission denied: {error_message}", status=403)

    if password_type not in ['mariadb', 'sftp']:
        return HttpResponse("Invalid password type")

    k8s_domain = None
    try:
        k8s_domain = k8s_get_domain(domain)
    except K8sNotFoundError:
        messages.error(request, "Domain not found in Kubernetes cluster. Cannot change password.")
        return redirect('view_domain', domain=domain_obj.domain_name)
    except K8sClientError as e:
        messages.error(request, f"Failed to fetch domain from Kubernetes: {e}")
        return redirect('view_domain', domain=domain_obj.domain_name)

    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if not new_password or not confirm_password:
            messages.error(request, "Both password fields are required.")
            return render(request, "main/change_password.html", {
                "domain": domain_obj,
                "password_type": password_type
            })

        if new_password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, "main/change_password.html", {
                "domain": domain_obj,
                "password_type": password_type
            })

        if len(new_password) < 8:
            messages.error(request, "Password must be at least 8 characters long.")
            return render(request, "main/change_password.html", {
                "domain": domain_obj,
                "password_type": password_type
            })

        namespace = domain_obj.namespace
        db_username = None

        if password_type == 'mariadb':
            password_label = "Database"

            if k8s_domain and k8s_domain.status:
                db_username = k8s_domain.status.database_username

            if not db_username:
                messages.error(request, "No database username found for this domain. Is the domain fully provisioned?")
                return render(request, "main/change_password.html", {
                    "domain": domain_obj,
                    "password_type": password_type
                })

            try:
                update_mariadb_user_password(db_username, new_password)
                k8s_update_database_password(namespace, new_password)
                messages.success(request, f"{password_label} password updated successfully.")

            except K8sClientError as e:
                logger.error(f"Failed to update database password K8s secret for {domain}: {e}")
                messages.error(request, f"Failed to update password in Kubernetes: {e}")
                return render(request, "main/change_password.html", {
                    "domain": domain_obj,
                    "password_type": password_type
                })
            except Exception as e:
                logger.error(f"Error updating MariaDB password for user {db_username}: {e}")
                messages.error(request, f"Failed to update MariaDB password: {e}")
                return render(request, "main/change_password.html", {
                    "domain": domain_obj,
                    "password_type": password_type
                })

        else:  # sftp
            password_label = "SFTP"

            try:
                k8s_update_sftp_password(namespace, new_password)
                messages.success(request, f"{password_label} password updated successfully.")

            except K8sClientError as e:
                logger.error(f"Failed to update SFTP password K8s secret for {domain}: {e}")
                messages.error(request, f"Failed to update password in Kubernetes: {e}")
                return render(request, "main/change_password.html", {
                    "domain": domain_obj,
                    "password_type": password_type
                })

        LogEntry.objects.create(
            content_object=domain_obj,
            actor=f"user:{request.user.username}",
            user=request.user,
            level="INFO",
            message=f"{password_label} password changed for {domain_obj.domain_name}",
            data={
                "domain_id": domain_obj.pk,
                "password_type": password_type,
                "user_id": request.user.id,
                "domain_owner_id": domain_obj.owner.id,
                "is_superuser": request.user.is_superuser,
                "db_username": db_username if password_type == 'mariadb' else None
            }
        )

        return redirect('view_domain', domain=domain_obj.domain_name)

    return render(request, "main/change_password.html", {
        "domain": domain_obj,
        "password_type": password_type
    })


def validate_package_limits(user, storage_size: int, cpu_limit: int, mem_limit: int):
    """Validate that user's package allows the requested resources."""
    pkg = user.profile.package
    if pkg is None:
        return

    existing_domains = Domain.objects.filter(owner=user)

    total_storage = sum(d.storage_size for d in existing_domains) + storage_size
    total_cpu = sum(d.cpu_limit for d in existing_domains) + cpu_limit
    total_mem = sum(d.mem_limit for d in existing_domains) + mem_limit

    errors = {}

    if total_storage > pkg.max_storage_size:
        errors['storage_size'] = (
            f"Total storage ({total_storage} GB) exceeds "
            f"package limit ({pkg.max_storage_size} GB)."
        )

    if total_cpu > pkg.max_cpu:
        errors['cpu_limit'] = (
            f"Total CPU ({total_cpu}m) exceeds "
            f"package limit ({pkg.max_cpu}m)."
        )

    if total_mem > pkg.max_memory:
        errors['mem_limit'] = (
            f"Total memory ({total_mem} MB) exceeds "
            f"package limit ({pkg.max_memory} MB)."
        )

    if errors:
        raise ValidationError(errors)


def _sync_domain_aliases(domain: Domain) -> None:
    """
    Sync domain aliases to K8s Domain CR.

    Reads all DomainAlias records for the domain and patches the CR
    so the operator updates nginx config and Ingress.
    """
    aliases = list(domain.aliases.values_list('alias_name', flat=True))
    try:
        k8s_patch_domain(domain.domain_name, {"aliases": aliases})
        logger.info(f"Synced {len(aliases)} aliases to Domain CR for {domain.domain_name}")
    except K8sNotFoundError:
        logger.warning(f"Domain CR not found for {domain.domain_name}, skipping alias sync")
    except K8sClientError as e:
        logger.error(f"Failed to sync aliases to Domain CR for {domain.domain_name}: {e}")
        raise


@login_required
def alias_list(request, pk):
    """List all aliases for a domain."""
    domain = get_object_or_404(Domain, pk=pk)
    if domain.owner != request.user and not request.user.is_superuser:
        return render(request, "main/error.html", {"error": "Permission denied."})

    aliases = domain.aliases.order_by('created_at')
    return render(request, 'main/list_aliases.html', {'domain': domain, 'aliases': aliases})


@login_required
def alias_add(request, pk):
    """Add a domain alias and sync to K8s."""
    domain = get_object_or_404(Domain, pk=pk)
    if domain.owner != request.user and not request.user.is_superuser:
        return render(request, "main/error.html", {"error": "Permission denied."})

    if request.method == 'POST':
        form = DomainAliasForm(request.POST)
        if form.is_valid():
            alias = form.save(commit=False)
            alias.domain = domain
            alias.save()

            try:
                _sync_domain_aliases(domain)
                messages.success(request, f"Alias '{alias.alias_name}' added successfully.")
            except K8sClientError as e:
                messages.warning(request, f"Alias saved but failed to sync to Kubernetes: {e}")

            return redirect('view_domain', domain=domain.domain_name)
    else:
        form = DomainAliasForm()
    return render(request, 'main/add_alias.html', {'domain': domain, 'form': form})


@login_required
def alias_delete(request, pk):
    """Delete a domain alias and sync to K8s."""
    alias = get_object_or_404(DomainAlias, pk=pk)
    domain = alias.domain

    if domain.owner != request.user and not request.user.is_superuser:
        return render(request, "main/error.html", {"error": "Permission denied."})

    if request.method == 'POST':
        alias_name = alias.alias_name
        alias.delete()

        try:
            _sync_domain_aliases(domain)
            messages.success(request, f"Alias '{alias_name}' deleted successfully.")
        except K8sClientError as e:
            messages.warning(request, f"Alias deleted but failed to sync to Kubernetes: {e}")

        return redirect('alias_list', pk=domain.pk)
    return render(request, 'main/delete_alias.html', {'alias': alias})
