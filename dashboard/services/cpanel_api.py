"""
cPanel/WHM API Client

Provides a client for interacting with WHM API and cPanel UAPI to:
- Test connection credentials
- List domains, databases, and email accounts (WHM API)
- Trigger and download full account backups

WHM API Documentation: https://api.docs.cpanel.net/openapi/whm/operation/
cPanel UAPI Documentation: https://api.docs.cpanel.net/openapi/cpanel/operation/

WHM API uses port 2087 and /json-api/{function} endpoint format.
cPanel UAPI uses port 2083 and /execute/{module}/{function} format.
"""

import logging
import requests
from typing import Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class CPanelAPIError(Exception):
    """Exception raised when cPanel/WHM API returns an error."""
    pass


class CPanelConnectionError(Exception):
    """Exception raised when connection to cPanel/WHM fails."""
    pass


@dataclass
class DatabaseInfo:
    """Information about a cPanel database."""
    name: str
    size_mb: float


@dataclass
class MailboxInfo:
    """Information about a cPanel email account."""
    email: str
    size_mb: float


@dataclass
class DomainInfo:
    """Information about a cPanel domain."""
    name: str
    type: str  # 'main', 'addon', 'sub', 'parked', 'alias'
    documentroot: str
    user: str  # cPanel username that owns this domain
    databases: list[DatabaseInfo] = field(default_factory=list)
    mailboxes: list[MailboxInfo] = field(default_factory=list)


class CPanelClient:
    """
    Client for WHM API and cPanel UAPI.

    For server-wide operations (listing all domains), uses WHM API (port 2087).
    For per-account operations, uses cPanel UAPI (port 2083).

    Authentication uses API tokens created in WHM > Development > Manage API Tokens.

    Usage:
        client = CPanelClient(
            hostname="whm.example.com",
            port=2087,  # WHM port
            username="root",  # WHM user (usually root or reseller)
            api_token="XXXXXXXXXXXXXXXXXXXX"
        )

        if client.test_connection():
            domains = client.list_domains()
            for domain in domains:
                print(f"{domain.name} ({domain.user}): {len(domain.databases)} DBs")
    """

    def __init__(
        self,
        hostname: str,
        port: int = 2087,
        username: str = 'root',
        api_token: str = '',
        verify_ssl: bool = True,
        timeout: int = 30,
    ):
        """
        Initialize the WHM/cPanel API client.

        Args:
            hostname: WHM server hostname or IP
            port: WHM port (usually 2087 for HTTPS)
            username: WHM username (root or reseller)
            api_token: WHM API token (from Manage API Tokens)
            verify_ssl: Whether to verify SSL certificate
            timeout: Request timeout in seconds
        """
        self.hostname = hostname
        self.port = port
        self.base_url = f"https://{hostname}:{port}"
        self.username = username
        self.api_token = api_token
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        # Set up session with WHM API token authentication
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'whm {username}:{api_token}',
        })

    def _whm_request(
        self,
        function: str,
        params: Optional[dict] = None,
        api_version: int = 1,
    ) -> dict:
        """
        Make a request to the WHM API.

        Args:
            function: WHM API function name (e.g., 'get_domain_info', 'listaccts')
            params: Query parameters
            api_version: API version (default 1)

        Returns:
            Parsed JSON response data

        Raises:
            CPanelConnectionError: If connection fails
            CPanelAPIError: If API returns an error
        """
        url = f"{self.base_url}/json-api/{function}"

        if params is None:
            params = {}
        params['api.version'] = api_version

        try:
            response = self.session.get(
                url,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )

            response.raise_for_status()
            data = response.json()

            # Check for API-level errors
            metadata = data.get('metadata', {})
            if metadata.get('result') == 0:
                reason = metadata.get('reason', 'Unknown error')
                raise CPanelAPIError(f"WHM API error: {reason}")

            return data.get('data', data)

        except requests.exceptions.SSLError as e:
            logger.error(f"SSL error connecting to WHM: {e}")
            raise CPanelConnectionError(f"SSL certificate error: {e}")
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error to WHM: {e}")
            raise CPanelConnectionError(f"Could not connect to WHM server: {e}")
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout connecting to WHM: {e}")
            raise CPanelConnectionError(f"Connection timed out: {e}")
        except requests.exceptions.HTTPError as e:
            if e.response is not None:
                if e.response.status_code == 401:
                    raise CPanelAPIError("Invalid credentials or API token")
                if e.response.status_code == 403:
                    raise CPanelAPIError("Access denied. Check API token permissions.")
            raise CPanelAPIError(f"HTTP error: {e}")
        except ValueError as e:
            raise CPanelAPIError(f"Invalid JSON response: {e}")

    def _uapi_request(
        self,
        cpanel_user: str,
        module: str,
        function: str,
        params: Optional[dict] = None,
        timeout: Optional[int] = None,
    ) -> dict:
        """
        Make a cPanel UAPI request via WHM (impersonating a cPanel user).

        Args:
            cpanel_user: cPanel username to impersonate
            module: UAPI module name (e.g., 'Email', 'Mysql')
            function: Function name within the module
            params: Additional parameters
            timeout: Optional custom timeout (uses self.timeout if not provided)

        Returns:
            Parsed JSON response data
        """
        url = f"{self.base_url}/json-api/cpanel"

        request_params = {
            'cpanel_jsonapi_user': cpanel_user,
            'cpanel_jsonapi_apiversion': 3,
            'cpanel_jsonapi_module': module,
            'cpanel_jsonapi_func': function,
        }
        if params:
            request_params.update(params)

        try:
            response = self.session.get(
                url,
                params=request_params,
                verify=self.verify_ssl,
                timeout=timeout or self.timeout,
            )
            response.raise_for_status()
            data = response.json()

            # Check for API-level errors
            result = data.get('result', {})
            if isinstance(result, dict) and result.get('status') == 0:
                errors = result.get('errors', ['Unknown error'])
                raise CPanelAPIError(f"cPanel UAPI error: {errors}")

            # Extract data from UAPI response
            if 'result' in data and 'data' in data.get('result', {}):
                return data['result']['data']
            return data.get('result', data)

        except requests.exceptions.RequestException as e:
            raise CPanelAPIError(f"UAPI request failed: {e}")

    def test_connection(self) -> bool:
        """
        Test if the credentials are valid.

        Returns:
            True if connection is successful

        Raises:
            CPanelConnectionError: If connection fails
            CPanelAPIError: If credentials are invalid
        """
        try:
            # Use version API to verify credentials
            self._whm_request('version')
            return True
        except (CPanelConnectionError, CPanelAPIError):
            raise

    def list_accounts(self) -> list[dict]:
        """
        List all cPanel accounts on the server.

        Returns:
            List of account dictionaries with user info
        """
        data = self._whm_request('listaccts')
        return data.get('acct', [])

    def list_domains(self) -> list[DomainInfo]:
        """
        List all domains on the WHM server.

        Returns:
            List of DomainInfo objects with user ownership info
        """
        data = self._whm_request('get_domain_info')

        domains = []
        domain_list = data.get('domains', [])

        for domain_data in domain_list:
            domain_name = domain_data.get('domain', '')
            if not domain_name:
                continue

            domain = DomainInfo(
                name=domain_name,
                type=domain_data.get('domain_type', 'main'),
                documentroot=domain_data.get('docroot', ''),
                user=domain_data.get('user', ''),
                databases=[],
                mailboxes=[],
            )
            domains.append(domain)

        # Populate databases and mailboxes for each domain
        # Group domains by user to minimize API calls
        users = set(d.user for d in domains if d.user)
        user_databases = {}

        for user in users:
            try:
                user_databases[user] = self._list_user_databases(user)
            except CPanelAPIError as e:
                logger.warning(f"Could not list databases for {user}: {e}")
                user_databases[user] = []

        # Assign databases to main domain of each user
        user_main_domains = {}
        for domain in domains:
            if domain.user and domain.type in ('main', 'primary'):
                user_main_domains[domain.user] = domain

        for user, dbs in user_databases.items():
            if user in user_main_domains:
                user_main_domains[user].databases = dbs

        # Get mailboxes for each domain
        for domain in domains:
            if domain.user:
                try:
                    domain.mailboxes = self._list_domain_mailboxes(domain.user, domain.name)
                except CPanelAPIError as e:
                    logger.warning(f"Could not list mailboxes for {domain.name}: {e}")
                    domain.mailboxes = []

        return domains

    def _list_user_databases(self, cpanel_user: str) -> list[DatabaseInfo]:
        """
        List MySQL databases for a cPanel user.

        Args:
            cpanel_user: cPanel username

        Returns:
            List of DatabaseInfo objects
        """
        try:
            data = self._uapi_request(cpanel_user, 'Mysql', 'list_databases')

            databases = []
            if isinstance(data, list):
                for db in data:
                    db_name = db.get('database', db.get('db', ''))
                    size_bytes = db.get('disk_usage', 0) or db.get('size', 0) or 0

                    # Handle string sizes
                    if isinstance(size_bytes, str):
                        size_mb = self._parse_size_to_mb(size_bytes)
                    else:
                        size_mb = size_bytes / (1024 * 1024) if size_bytes else 0

                    if db_name:
                        databases.append(DatabaseInfo(
                            name=db_name,
                            size_mb=round(size_mb, 2),
                        ))

            return databases

        except CPanelAPIError as e:
            logger.warning(f"Could not list databases for {cpanel_user}: {e}")
            return []

    def _list_domain_mailboxes(self, cpanel_user: str, domain: str) -> list[MailboxInfo]:
        """
        List email accounts for a specific domain.

        Args:
            cpanel_user: cPanel username that owns the domain
            domain: Domain name

        Returns:
            List of MailboxInfo objects
        """
        try:
            data = self._uapi_request(
                cpanel_user,
                'Email',
                'list_pops_with_disk',
                {'domain': domain}
            )

            mailboxes = []
            if isinstance(data, list):
                for account in data:
                    email = account.get('email', '')
                    disk_used = account.get('diskused', 0) or account.get('_diskused', 0)

                    if isinstance(disk_used, str):
                        size_mb = self._parse_size_to_mb(disk_used)
                    elif isinstance(disk_used, (int, float)):
                        # Assume bytes if large number, MB otherwise
                        size_mb = disk_used / (1024 * 1024) if disk_used > 10000 else disk_used
                    else:
                        size_mb = 0

                    if email:
                        mailboxes.append(MailboxInfo(
                            email=email,
                            size_mb=round(size_mb, 2),
                        ))

            return mailboxes

        except CPanelAPIError as e:
            logger.warning(f"Could not list mailboxes for {domain}: {e}")
            return []

    def _parse_size_to_mb(self, size_str: str) -> float:
        """Parse a human-readable size string to MB."""
        if not size_str:
            return 0.0

        size_str = str(size_str).strip().upper()
        try:
            if size_str.endswith('GB') or size_str.endswith('G'):
                return float(size_str.rstrip('GB').rstrip('G').strip()) * 1024
            elif size_str.endswith('MB') or size_str.endswith('M'):
                return float(size_str.rstrip('MB').rstrip('M').strip())
            elif size_str.endswith('KB') or size_str.endswith('K'):
                return float(size_str.rstrip('KB').rstrip('K').strip()) / 1024
            elif size_str.endswith('B'):
                return float(size_str.rstrip('B').strip()) / (1024 * 1024)
            else:
                # Assume bytes if numeric
                return float(size_str) / (1024 * 1024)
        except (ValueError, AttributeError):
            return 0.0

    def get_account_backup_list(self, cpanel_user: str) -> list[dict]:
        """
        List available backups for a cPanel account.

        Args:
            cpanel_user: cPanel username

        Returns:
            List of backup info dicts
        """
        try:
            data = self._uapi_request(cpanel_user, 'Backup', 'list_backups')
            return data if isinstance(data, list) else []
        except CPanelAPIError:
            return []

    def create_user_backup(self, cpanel_user: str) -> str:
        """
        Trigger a full backup for a cPanel user account.

        Args:
            cpanel_user: cPanel username

        Returns:
            Backup status/PID
        """
        # Use cPanel UAPI to trigger backup (via WHM impersonation)
        data = self._uapi_request(
            cpanel_user,
            'Backup',
            'fullbackup_to_homedir'
        )
        # UAPI returns pid of the backup process
        if isinstance(data, dict):
            return data.get('pid', 'Backup started')
        return 'Backup started'

    def trigger_backup_to_sftp(
        self,
        cpanel_user: str,
        sftp_host: str,
        sftp_port: int,
        sftp_user: str,
        sftp_password: str,
        remote_dir: str = '',
    ) -> str:
        """
        Trigger a backup that will be pushed to an SFTP server.

        Uses cPanel UAPI Backup/fullbackup_to_scp_with_password.
        cPanel will create the backup and push it to the specified SFTP server.

        Args:
            cpanel_user: cPanel account to backup
            sftp_host: Destination SFTP hostname
            sftp_port: Destination SFTP port
            sftp_user: SFTP username
            sftp_password: SFTP password
            remote_dir: Remote directory path (relative to SFTP user home)

        Returns:
            Backup PID or status message
        """
        # Use longer timeout for backup trigger - cPanel may validate SFTP connection
        data = self._uapi_request(
            cpanel_user,
            'Backup',
            'fullbackup_to_scp_with_password',
            {
                'host': sftp_host,
                'port': str(sftp_port),
                'username': sftp_user,
                'password': sftp_password,
                'directory': remote_dir,
            },
            timeout=300,  # 5 minutes for backup trigger
        )
        if isinstance(data, dict):
            return data.get('pid', 'Backup started')
        return 'Backup started'

    def get_backup_status(self, task_id: str) -> dict:
        """
        Check the status of a backup task.

        Args:
            task_id: Task ID from create_user_backup

        Returns:
            Status dict with 'state' and 'result' keys
        """
        data = self._whm_request('background_mysql_backup_status', {
            'taskid': task_id,
        })
        return data

    def download_account_backup(
        self,
        cpanel_user: str,
        dest_path: str,
        progress_callback: Optional[callable] = None,
    ) -> str:
        """
        Download a full backup for a cPanel account.

        Uses WHM API to fetch the backup directly.

        Args:
            cpanel_user: cPanel username
            dest_path: Local path to save the backup
            progress_callback: Optional callback(downloaded_bytes, total_bytes)

        Returns:
            Path to the downloaded file
        """
        # Use WHM API to download backup
        url = f"{self.base_url}/json-api/fetch_transfer_session_remote_restore_full_backup"

        params = {
            'user': cpanel_user,
            'api.version': 1,
        }

        try:
            response = self.session.get(
                url,
                params=params,
                stream=True,
                verify=self.verify_ssl,
                timeout=None,  # No timeout for large downloads
            )
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            chunk_size = 1024 * 1024  # 1MB chunks

            with open(dest_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if progress_callback and total_size:
                            progress_callback(downloaded, total_size)

            return dest_path

        except requests.exceptions.RequestException as e:
            raise CPanelAPIError(f"Failed to download backup: {e}")

    def list_backup_files_for_user(self, cpanel_user: str) -> list[dict]:
        """
        List backup files available for a cPanel user.

        Args:
            cpanel_user: cPanel username

        Returns:
            List of dicts with file info
        """
        try:
            data = self._uapi_request(
                cpanel_user,
                'Fileman',
                'list_files',
                {
                    'dir': f'/home/{cpanel_user}',
                    'include_mime': 0,
                    'include_hash': 0,
                    'include_permissions': 0,
                }
            )

            backups = []
            if isinstance(data, list):
                for item in data:
                    filename = item.get('file', '')
                    if filename.startswith('backup-') and filename.endswith('.tar.gz'):
                        backups.append({
                            'file': filename,
                            'size': item.get('size', 0),
                            'mtime': item.get('mtime', 0),
                            'path': f"/home/{cpanel_user}/{filename}",
                        })

            backups.sort(key=lambda x: x.get('mtime', 0), reverse=True)
            return backups

        except CPanelAPIError:
            return []

    def trigger_and_download_backup(
        self,
        cpanel_user: str,
        dest_path: str,
        progress_callback: Optional[callable] = None,
        timeout: int = 3600,
    ) -> str:
        """
        Trigger a backup for a user and download it once complete.

        Args:
            cpanel_user: cPanel username to backup
            dest_path: Local path to save the backup
            progress_callback: Optional callback(stage, message, percent)
            timeout: Maximum time to wait for backup in seconds

        Returns:
            Path to downloaded backup file

        Raises:
            CPanelAPIError: If backup fails
            TimeoutError: If backup doesn't complete in time
        """
        import time

        def notify(stage, message, percent=None):
            if progress_callback:
                progress_callback(stage, message, percent)

        # Stage 1: Check for existing recent backup first
        notify('checking', 'Checking for existing backups...', 5)
        existing_backups = self.list_backup_files_for_user(cpanel_user)

        if existing_backups:
            # Use existing backup if it's less than 1 hour old
            newest = existing_backups[0]
            age = time.time() - newest.get('mtime', 0)
            if age < 3600:  # 1 hour
                notify('downloading', f"Using recent backup: {newest['file']}", 30)
                return self._download_backup_file(
                    cpanel_user,
                    newest['file'],
                    dest_path,
                    progress_callback
                )

        # Stage 2: Trigger new backup
        notify('triggering', 'Triggering cPanel backup...', 10)
        task_id = self.create_user_backup(cpanel_user)
        logger.info(f"Triggered backup for {cpanel_user}, task: {task_id}")

        # Stage 3: Wait for backup to complete
        notify('waiting', 'Waiting for backup to complete...', 15)
        start_time = time.time()

        while time.time() - start_time < timeout:
            # Check for new backup files
            backups = self.list_backup_files_for_user(cpanel_user)
            for backup in backups:
                # Look for backup created after we started
                if backup.get('mtime', 0) > start_time:
                    notify('downloading', f"Backup ready: {backup['file']}", 30)
                    return self._download_backup_file(
                        cpanel_user,
                        backup['file'],
                        dest_path,
                        progress_callback
                    )

            elapsed = int(time.time() - start_time)
            notify('waiting', f'Waiting for backup... ({elapsed}s)', 20)
            time.sleep(10)

        raise TimeoutError("Backup did not complete within timeout")

    def _download_backup_file(
        self,
        cpanel_user: str,
        filename: str,
        dest_path: str,
        progress_callback: Optional[callable] = None,
    ) -> str:
        """
        Download a specific backup file for a user.

        Args:
            cpanel_user: cPanel username
            filename: Backup filename
            dest_path: Local path to save
            progress_callback: Optional progress callback

        Returns:
            Path to downloaded file
        """
        def notify(stage, message, percent=None):
            if progress_callback:
                progress_callback(stage, message, percent)

        # Use WHM download endpoint (port 2087) - WHM auth works here
        url = f"{self.base_url}/download"

        params = {
            'file': f'/home/{cpanel_user}/{filename}',
            'skipaccount': 1,  # Required for WHM to access user files
        }

        try:
            response = self.session.get(
                url,
                params=params,
                stream=True,
                verify=self.verify_ssl,
                timeout=None,
            )
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            chunk_size = 1024 * 1024  # 1MB

            with open(dest_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            percent = 30 + int((downloaded / total_size) * 60)
                            size_mb = downloaded / (1024 * 1024)
                            total_mb = total_size / (1024 * 1024)
                            notify('downloading', f'Downloaded {size_mb:.1f} / {total_mb:.1f} MB', percent)

            notify('complete', 'Backup download complete', 100)
            return dest_path

        except requests.exceptions.RequestException as e:
            raise CPanelAPIError(f"Failed to download backup: {e}")


def serialize_domain_info(domain: DomainInfo) -> dict:
    """Convert DomainInfo to a JSON-serializable dict."""
    return {
        'name': domain.name,
        'type': domain.type,
        'documentroot': domain.documentroot,
        'user': domain.user,
        'databases': [
            {'name': db.name, 'size_mb': db.size_mb}
            for db in domain.databases
        ],
        'mailboxes': [
            {'email': mb.email, 'size_mb': mb.size_mb}
            for mb in domain.mailboxes
        ],
    }
