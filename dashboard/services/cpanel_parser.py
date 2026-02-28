"""
cPanel Backup Parser

Parses cPanel full backup tar.gz files and extracts components:
- Website files (public_html/)
- MySQL databases (mysql/*.sql)
- Mailboxes (mail/domain/user/)
"""

import logging
import os
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class CPanelParserError(Exception):
    """Exception raised when parsing cPanel backup fails."""
    pass


@dataclass
class BackupMetadata:
    """Metadata extracted from cPanel backup."""
    cpanel_user: str
    main_domain: str
    backup_date: str
    databases: list[str]
    domains: list[str]
    mailboxes: dict[str, list[str]]  # domain -> [local_parts]


class CPanelBackupParser:
    """
    Parse cPanel full backup tar.gz structure.

    cPanel backups have this structure:
    backup-MM.DD.YYYY_HH-MM-SS_USERNAME.tar.gz
    ├── homedir.tar          # All files from /home/user
    │   ├── public_html/     # Main website files
    │   ├── mail/
    │   │   └── domain.com/
    │   │       ├── user1/   # Maildir format
    │   │       │   ├── cur/
    │   │       │   ├── new/
    │   │       │   └── tmp/
    │   │       └── user2/
    │   └── ...
    ├── mysql/
    │   ├── database1.sql
    │   └── database2.sql
    ├── dnszones/
    ├── etc/
    └── ...

    Usage:
        parser = CPanelBackupParser('/path/to/backup.tar.gz')
        metadata = parser.get_metadata()

        # Extract website files
        parser.extract_public_html('/tmp/output/html')

        # Extract a specific database
        parser.extract_database('user_wordpress', '/tmp/output/db.sql')

        # Extract a mailbox
        parser.extract_mailbox('example.com', 'info', '/tmp/output/mailbox')
    """

    def __init__(self, backup_path: str):
        """
        Initialize parser with path to cPanel backup tar.gz.

        Args:
            backup_path: Path to the cPanel backup tar.gz file
        """
        self.backup_path = backup_path
        self._metadata: Optional[BackupMetadata] = None
        self._temp_dir: Optional[str] = None
        self._homedir_extracted = False

        if not os.path.exists(backup_path):
            raise CPanelParserError(f"Backup file not found: {backup_path}")

        if not tarfile.is_tarfile(backup_path):
            raise CPanelParserError(f"Not a valid tar file: {backup_path}")

    def _ensure_temp_dir(self) -> str:
        """Create temporary directory for extraction if needed."""
        if self._temp_dir is None:
            self._temp_dir = tempfile.mkdtemp(prefix='cpanel_backup_')
        return self._temp_dir

    def _extract_homedir(self) -> str:
        """
        Extract homedir from the backup to temp directory.

        Handles two cPanel backup formats:
        1. Direct homedir/ directory in backup
        2. homedir.tar nested archive

        Returns:
            Path to extracted homedir directory
        """
        if self._homedir_extracted:
            return os.path.join(self._ensure_temp_dir(), 'homedir')

        temp_dir = self._ensure_temp_dir()
        homedir_path = os.path.join(temp_dir, 'homedir')

        try:
            with tarfile.open(self.backup_path, 'r:gz') as outer_tar:
                # First, check if homedir/ directory exists directly
                homedir_dir_member = None
                homedir_tar_member = None

                for member in outer_tar.getmembers():
                    # Check for direct homedir/ directory
                    if member.name == 'homedir' or member.name.endswith('/homedir'):
                        if member.isdir():
                            homedir_dir_member = member
                            break
                    # Check for homedir.tar
                    if member.name.endswith('homedir.tar') or member.name == 'homedir.tar':
                        homedir_tar_member = member

                if homedir_dir_member is not None:
                    # Format: direct homedir/ directory - extract all homedir/* members
                    logger.info("Detected direct homedir/ directory format")
                    os.makedirs(homedir_path, exist_ok=True)

                    # Get the prefix to strip (e.g., "homedir/" or "backup-xxx/homedir/")
                    prefix = homedir_dir_member.name + '/'

                    for member in outer_tar.getmembers():
                        if member.name.startswith(prefix) or member.name == homedir_dir_member.name:
                            # Strip the prefix to get relative path
                            if member.name == homedir_dir_member.name:
                                continue  # Skip the directory itself
                            rel_path = member.name[len(prefix):]
                            if rel_path:
                                member.name = rel_path
                                outer_tar.extract(member, homedir_path)

                elif homedir_tar_member is not None:
                    # Format: homedir.tar nested archive
                    logger.info("Detected homedir.tar nested archive format")
                    homedir_tar_path = os.path.join(temp_dir, 'homedir.tar')

                    outer_tar.extract(homedir_tar_member, temp_dir)
                    extracted_path = os.path.join(temp_dir, homedir_tar_member.name)

                    if extracted_path != homedir_tar_path:
                        os.rename(extracted_path, homedir_tar_path)

                    os.makedirs(homedir_path, exist_ok=True)
                    with tarfile.open(homedir_tar_path, 'r') as homedir_tar:
                        homedir_tar.extractall(homedir_path)
                else:
                    raise CPanelParserError("Neither homedir/ directory nor homedir.tar found in backup")

            self._homedir_extracted = True
            return homedir_path

        except tarfile.TarError as e:
            raise CPanelParserError(f"Failed to extract homedir: {e}")

    def get_metadata(self) -> BackupMetadata:
        """
        Parse backup and return metadata without full extraction.

        Returns:
            BackupMetadata with information about backup contents
        """
        if self._metadata is not None:
            return self._metadata

        cpanel_user = ''
        main_domain = ''
        backup_date = ''
        databases = []
        domains = []
        mailboxes: dict[str, list[str]] = {}

        try:
            # Parse filename for user and date
            # Format: backup-MM.DD.YYYY_HH-MM-SS_USERNAME.tar.gz
            filename = os.path.basename(self.backup_path)
            if filename.startswith('backup-'):
                parts = filename.replace('.tar.gz', '').split('_')
                if len(parts) >= 3:
                    backup_date = parts[0].replace('backup-', '')
                    cpanel_user = parts[-1]

            with tarfile.open(self.backup_path, 'r:gz') as tar:
                for member in tar.getmembers():
                    name = member.name

                    # Find databases in mysql/ directory
                    if '/mysql/' in name or name.startswith('mysql/'):
                        if name.endswith('.sql'):
                            db_name = os.path.basename(name).replace('.sql', '')
                            if db_name not in databases:
                                databases.append(db_name)

                    # Find main domain from userdata
                    if 'userdata/main' in name:
                        try:
                            f = tar.extractfile(member)
                            if f:
                                content = f.read().decode('utf-8', errors='ignore')
                                for line in content.split('\n'):
                                    if line.startswith('main_domain:'):
                                        main_domain = line.split(':', 1)[1].strip()
                                        break
                        except Exception:
                            pass

            # For mailboxes, we need to peek into homedir.tar
            # This is more complex, so we'll scan for mail directories
            homedir_path = self._extract_homedir()
            mail_base = os.path.join(homedir_path, 'mail')

            if os.path.exists(mail_base):
                for domain_dir in os.listdir(mail_base):
                    domain_path = os.path.join(mail_base, domain_dir)
                    if os.path.isdir(domain_path) and '.' in domain_dir:
                        domains.append(domain_dir)
                        mailboxes[domain_dir] = []
                        for user_dir in os.listdir(domain_path):
                            user_path = os.path.join(domain_path, user_dir)
                            # Check if it looks like a maildir
                            if os.path.isdir(user_path):
                                cur_dir = os.path.join(user_path, 'cur')
                                new_dir = os.path.join(user_path, 'new')
                                if os.path.exists(cur_dir) or os.path.exists(new_dir):
                                    mailboxes[domain_dir].append(user_dir)

            # Also check public_html for the main domain
            public_html = os.path.join(homedir_path, 'public_html')
            if os.path.exists(public_html) and main_domain and main_domain not in domains:
                domains.insert(0, main_domain)

            self._metadata = BackupMetadata(
                cpanel_user=cpanel_user,
                main_domain=main_domain,
                backup_date=backup_date,
                databases=databases,
                domains=domains,
                mailboxes=mailboxes,
            )

            return self._metadata

        except tarfile.TarError as e:
            raise CPanelParserError(f"Failed to parse backup metadata: {e}")

    def extract_public_html(self, dest_path: str) -> str:
        """
        Extract public_html directory from the backup.

        Args:
            dest_path: Destination directory path

        Returns:
            Path to extracted public_html directory
        """
        homedir_path = self._extract_homedir()
        public_html_src = os.path.join(homedir_path, 'public_html')

        if not os.path.exists(public_html_src):
            raise CPanelParserError("public_html not found in backup")

        # Create destination and copy
        os.makedirs(dest_path, exist_ok=True)
        self._copy_directory(public_html_src, dest_path)

        logger.info(f"Extracted public_html to {dest_path}")
        return dest_path

    def extract_database(self, db_name: str, dest_path: str) -> str:
        """
        Extract a specific database SQL file from the backup.

        Args:
            db_name: Name of the database (without .sql extension)
            dest_path: Destination file path for the SQL file

        Returns:
            Path to extracted SQL file
        """
        temp_dir = self._ensure_temp_dir()

        try:
            with tarfile.open(self.backup_path, 'r:gz') as tar:
                for member in tar.getmembers():
                    # Look for the database file
                    if member.name.endswith(f'{db_name}.sql'):
                        # Extract to temp first
                        tar.extract(member, temp_dir)
                        extracted_path = os.path.join(temp_dir, member.name)

                        # Move to destination
                        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                        os.rename(extracted_path, dest_path)

                        logger.info(f"Extracted database {db_name} to {dest_path}")
                        return dest_path

            raise CPanelParserError(f"Database {db_name} not found in backup")

        except tarfile.TarError as e:
            raise CPanelParserError(f"Failed to extract database {db_name}: {e}")

    def extract_mailbox(self, domain: str, local_part: str, dest_path: str) -> str:
        """
        Extract a specific mailbox directory from the backup.

        The mailbox is in Maildir format with cur/, new/, tmp/ subdirectories.

        Args:
            domain: Domain name (e.g., 'example.com')
            local_part: Local part of email (e.g., 'info' for info@example.com)
            dest_path: Destination directory path

        Returns:
            Path to extracted mailbox directory
        """
        homedir_path = self._extract_homedir()
        mailbox_src = os.path.join(homedir_path, 'mail', domain, local_part)

        if not os.path.exists(mailbox_src):
            raise CPanelParserError(
                f"Mailbox {local_part}@{domain} not found in backup"
            )

        # Verify it's a valid maildir
        cur_dir = os.path.join(mailbox_src, 'cur')
        new_dir = os.path.join(mailbox_src, 'new')
        if not os.path.exists(cur_dir) and not os.path.exists(new_dir):
            raise CPanelParserError(
                f"Invalid mailbox format for {local_part}@{domain}: missing cur/ or new/"
            )

        # Create destination and copy
        os.makedirs(dest_path, exist_ok=True)
        self._copy_directory(mailbox_src, dest_path)

        logger.info(f"Extracted mailbox {local_part}@{domain} to {dest_path}")
        return dest_path

    def extract_addon_domain_files(self, domain: str, dest_path: str) -> str:
        """
        Extract files for an addon domain.

        Addon domains are typically in a subdirectory of the home folder.

        Args:
            domain: Addon domain name
            dest_path: Destination directory path

        Returns:
            Path to extracted files
        """
        homedir_path = self._extract_homedir()

        # Addon domains can be in various locations
        possible_paths = [
            os.path.join(homedir_path, domain),
            os.path.join(homedir_path, domain.replace('.', '_')),
            os.path.join(homedir_path, 'public_html', domain),
        ]

        for src_path in possible_paths:
            if os.path.exists(src_path) and os.path.isdir(src_path):
                os.makedirs(dest_path, exist_ok=True)
                self._copy_directory(src_path, dest_path)
                logger.info(f"Extracted addon domain {domain} from {src_path}")
                return dest_path

        raise CPanelParserError(
            f"Files for addon domain {domain} not found in backup"
        )

    def list_databases(self) -> list[str]:
        """
        List all databases in the backup.

        Returns:
            List of database names (without .sql extension)
        """
        databases = []

        try:
            with tarfile.open(self.backup_path, 'r:gz') as tar:
                for member in tar.getmembers():
                    if '/mysql/' in member.name or member.name.startswith('mysql/'):
                        if member.name.endswith('.sql'):
                            db_name = os.path.basename(member.name).replace('.sql', '')
                            if db_name not in databases:
                                databases.append(db_name)

            return databases

        except tarfile.TarError as e:
            raise CPanelParserError(f"Failed to list databases: {e}")

    def list_mailboxes(self, domain: str) -> list[str]:
        """
        List all mailboxes for a domain in the backup.

        Args:
            domain: Domain name

        Returns:
            List of local parts (usernames)
        """
        homedir_path = self._extract_homedir()
        mail_domain_path = os.path.join(homedir_path, 'mail', domain)

        if not os.path.exists(mail_domain_path):
            return []

        mailboxes = []
        for user_dir in os.listdir(mail_domain_path):
            user_path = os.path.join(mail_domain_path, user_dir)
            if os.path.isdir(user_path):
                # Check if it's a valid maildir
                cur_dir = os.path.join(user_path, 'cur')
                new_dir = os.path.join(user_path, 'new')
                if os.path.exists(cur_dir) or os.path.exists(new_dir):
                    mailboxes.append(user_dir)

        return mailboxes

    def get_database_size(self, db_name: str) -> int:
        """
        Get the size of a database SQL file in bytes.

        Args:
            db_name: Database name

        Returns:
            Size in bytes
        """
        try:
            with tarfile.open(self.backup_path, 'r:gz') as tar:
                for member in tar.getmembers():
                    if member.name.endswith(f'{db_name}.sql'):
                        return member.size

            return 0

        except tarfile.TarError:
            return 0

    def get_mailbox_size(self, domain: str, local_part: str) -> int:
        """
        Get the total size of a mailbox in bytes.

        Args:
            domain: Domain name
            local_part: Local part of email

        Returns:
            Size in bytes
        """
        homedir_path = self._extract_homedir()
        mailbox_path = os.path.join(homedir_path, 'mail', domain, local_part)

        if not os.path.exists(mailbox_path):
            return 0

        total_size = 0
        for dirpath, dirnames, filenames in os.walk(mailbox_path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                total_size += os.path.getsize(filepath)

        return total_size

    def _copy_directory(self, src: str, dest: str) -> None:
        """
        Recursively copy a directory.

        Args:
            src: Source directory
            dest: Destination directory
        """
        import shutil

        for item in os.listdir(src):
            src_path = os.path.join(src, item)
            dest_path = os.path.join(dest, item)

            if os.path.isdir(src_path):
                shutil.copytree(src_path, dest_path, dirs_exist_ok=True)
            else:
                shutil.copy2(src_path, dest_path)

    def cleanup(self) -> None:
        """
        Clean up temporary files created during parsing.

        Call this when done with the parser to free disk space.
        """
        if self._temp_dir and os.path.exists(self._temp_dir):
            import shutil
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None
            self._homedir_extracted = False

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup temp files."""
        self.cleanup()
        return False
