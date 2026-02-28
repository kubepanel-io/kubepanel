"""
cPanel to KubePanel Transformer

Transforms cPanel backup format to KubePanel-compatible archive format.

KubePanel expects:
- html/ directory (website files)
- database.sql (optional, MariaDB dump)
- manifest.json (optional, metadata)
"""

import json
import logging
import os
import tarfile
import tempfile
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


class CPanelTransformerError(Exception):
    """Exception raised when transformation fails."""
    pass


class CPanelTransformer:
    """
    Transform cPanel backup components to KubePanel format.

    KubePanel's UploadRestoreFilesView expects tar.gz archives with:
    - html/ or www/ directory containing website files
    - database.sql file with MariaDB dump
    - manifest.json (optional) with metadata

    Usage:
        transformer = CPanelTransformer()

        # Create restore archive from extracted components
        archive_path = transformer.create_restore_archive(
            public_html_path='/tmp/extracted/public_html',
            database_sql_path='/tmp/extracted/db.sql',
            output_path='/tmp/kubepanel-restore.tar.gz',
            metadata={'source': 'cpanel', 'domain': 'example.com'}
        )

        # Create mailbox archive for import
        mailbox_path = transformer.create_mailbox_archive(
            maildir_path='/tmp/extracted/mail/example.com/info',
            local_part='info',
            output_path='/tmp/info-mailbox.tar.gz'
        )
    """

    def create_restore_archive(
        self,
        public_html_path: Optional[str],
        database_sql_path: Optional[str],
        output_path: str,
        metadata: Optional[dict] = None,
    ) -> str:
        """
        Create a KubePanel-compatible restore archive.

        Args:
            public_html_path: Path to public_html directory (or None to skip files)
            database_sql_path: Path to database SQL file (or None to skip database)
            output_path: Output path for the tar.gz archive
            metadata: Optional metadata dict for manifest.json

        Returns:
            Path to created archive

        Raises:
            CPanelTransformerError: If transformation fails
        """
        if not public_html_path and not database_sql_path:
            raise CPanelTransformerError(
                "At least one of public_html_path or database_sql_path is required"
            )

        # Validate inputs
        if public_html_path and not os.path.exists(public_html_path):
            raise CPanelTransformerError(
                f"public_html directory not found: {public_html_path}"
            )
        if database_sql_path and not os.path.exists(database_sql_path):
            raise CPanelTransformerError(
                f"Database SQL file not found: {database_sql_path}"
            )

        try:
            # Create parent directory for output
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            with tarfile.open(output_path, 'w:gz') as tar:
                # Add website files as html/
                if public_html_path:
                    self._add_directory_to_tar(
                        tar,
                        public_html_path,
                        arcname='html'
                    )
                    logger.info(f"Added website files to archive as html/")

                # Add database SQL file
                if database_sql_path:
                    tar.add(database_sql_path, arcname='database.sql')
                    logger.info(f"Added database.sql to archive")

                # Create and add manifest.json
                manifest = self._create_manifest(
                    has_files=public_html_path is not None,
                    has_database=database_sql_path is not None,
                    extra_metadata=metadata,
                )
                self._add_json_to_tar(tar, manifest, 'manifest.json')
                logger.info(f"Added manifest.json to archive")

            logger.info(f"Created restore archive: {output_path}")
            return output_path

        except Exception as e:
            # Clean up partial file on error
            if os.path.exists(output_path):
                os.unlink(output_path)
            raise CPanelTransformerError(f"Failed to create restore archive: {e}")

    def create_mailbox_archive(
        self,
        maildir_path: str,
        local_part: str,
        output_path: str,
    ) -> str:
        """
        Create a mailbox archive for KubePanel mail import.

        The archive structure should be:
        {local_part}/
        ├── cur/
        ├── new/
        └── tmp/

        This matches what import_mailbox() in mail.py expects.

        Args:
            maildir_path: Path to the Maildir directory
            local_part: Local part of the email (e.g., 'info' for info@example.com)
            output_path: Output path for the tar.gz archive

        Returns:
            Path to created archive
        """
        if not os.path.exists(maildir_path):
            raise CPanelTransformerError(
                f"Maildir not found: {maildir_path}"
            )

        # Verify it's a valid Maildir
        cur_path = os.path.join(maildir_path, 'cur')
        new_path = os.path.join(maildir_path, 'new')
        if not os.path.exists(cur_path) and not os.path.exists(new_path):
            raise CPanelTransformerError(
                f"Invalid Maildir format: missing cur/ or new/ in {maildir_path}"
            )

        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            with tarfile.open(output_path, 'w:gz') as tar:
                # Add Maildir contents under local_part/
                self._add_directory_to_tar(
                    tar,
                    maildir_path,
                    arcname=local_part
                )

            logger.info(f"Created mailbox archive: {output_path}")
            return output_path

        except Exception as e:
            if os.path.exists(output_path):
                os.unlink(output_path)
            raise CPanelTransformerError(f"Failed to create mailbox archive: {e}")

    def transform_database_sql(
        self,
        input_path: str,
        output_path: str,
        strip_prefix: Optional[str] = None,
        new_db_name: Optional[str] = None,
    ) -> str:
        """
        Transform a cPanel database SQL dump.

        cPanel databases typically have a prefix (e.g., 'username_').
        This method can optionally strip that prefix and rename the database.

        Args:
            input_path: Path to source SQL file
            output_path: Path to output SQL file
            strip_prefix: Prefix to strip from table names (e.g., 'user_')
            new_db_name: New database name (if different from original)

        Returns:
            Path to transformed SQL file
        """
        if not os.path.exists(input_path):
            raise CPanelTransformerError(f"SQL file not found: {input_path}")

        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            with open(input_path, 'r', encoding='utf-8', errors='replace') as infile:
                with open(output_path, 'w', encoding='utf-8') as outfile:
                    for line in infile:
                        transformed_line = line

                        # Replace database name in USE and CREATE DATABASE statements
                        if new_db_name:
                            if line.strip().upper().startswith('USE '):
                                transformed_line = f"USE `{new_db_name}`;\n"
                            elif 'CREATE DATABASE' in line.upper():
                                # Skip CREATE DATABASE - KubePanel creates the DB
                                continue

                        # Strip prefix from table names if specified
                        if strip_prefix:
                            transformed_line = self._strip_table_prefix(
                                transformed_line,
                                strip_prefix
                            )

                        outfile.write(transformed_line)

            logger.info(f"Transformed database SQL: {output_path}")
            return output_path

        except Exception as e:
            if os.path.exists(output_path):
                os.unlink(output_path)
            raise CPanelTransformerError(f"Failed to transform database SQL: {e}")

    def _strip_table_prefix(self, line: str, prefix: str) -> str:
        """
        Strip prefix from table names in SQL statements.

        Handles:
        - CREATE TABLE `prefix_tablename`
        - INSERT INTO `prefix_tablename`
        - DROP TABLE IF EXISTS `prefix_tablename`
        - ALTER TABLE `prefix_tablename`
        """
        import re

        # Pattern to match table names with the prefix
        # Matches: `prefix_name` or prefix_name
        pattern = rf'(`?){re.escape(prefix)}(\w+)(`?)'

        def replace_match(match):
            quote_start = match.group(1)
            table_name = match.group(2)
            quote_end = match.group(3)
            return f'{quote_start}{table_name}{quote_end}'

        # Only apply to SQL statements that reference tables
        sql_keywords = [
            'CREATE TABLE', 'INSERT INTO', 'DROP TABLE', 'ALTER TABLE',
            'TRUNCATE TABLE', 'LOCK TABLES', 'UNLOCK TABLES',
            'REFERENCES', 'UPDATE', 'DELETE FROM'
        ]

        line_upper = line.upper()
        for keyword in sql_keywords:
            if keyword in line_upper:
                return re.sub(pattern, replace_match, line)

        return line

    def _create_manifest(
        self,
        has_files: bool,
        has_database: bool,
        extra_metadata: Optional[dict] = None,
    ) -> dict:
        """
        Create manifest.json content.

        Args:
            has_files: Whether archive contains website files
            has_database: Whether archive contains database
            extra_metadata: Additional metadata to include

        Returns:
            Manifest dictionary
        """
        manifest = {
            'version': '1.0',
            'source': 'cpanel-migration',
            'created_at': datetime.utcnow().isoformat() + 'Z',
            'contents': {
                'files': has_files,
                'database': has_database,
            },
        }

        if extra_metadata:
            manifest.update(extra_metadata)

        return manifest

    def _add_directory_to_tar(
        self,
        tar: tarfile.TarFile,
        src_path: str,
        arcname: str,
    ) -> None:
        """
        Add a directory to a tar archive with a custom archive name.

        Args:
            tar: Open TarFile object
            src_path: Source directory path
            arcname: Name to use in the archive
        """
        for root, dirs, files in os.walk(src_path):
            # Calculate relative path within the source directory
            rel_path = os.path.relpath(root, src_path)

            # Build archive path
            if rel_path == '.':
                arc_root = arcname
            else:
                arc_root = os.path.join(arcname, rel_path)

            # Add directory entry
            tar.add(root, arcname=arc_root, recursive=False)

            # Add files
            for file in files:
                file_path = os.path.join(root, file)
                arc_path = os.path.join(arc_root, file)
                tar.add(file_path, arcname=arc_path)

    def _add_json_to_tar(
        self,
        tar: tarfile.TarFile,
        data: dict,
        arcname: str,
    ) -> None:
        """
        Add a JSON object to a tar archive as a file.

        Args:
            tar: Open TarFile object
            data: Dictionary to serialize as JSON
            arcname: Filename in the archive
        """
        import io

        json_bytes = json.dumps(data, indent=2).encode('utf-8')
        json_buffer = io.BytesIO(json_bytes)

        info = tarfile.TarInfo(name=arcname)
        info.size = len(json_bytes)

        tar.addfile(info, json_buffer)


def transform_cpanel_backup_for_domain(
    parser,  # CPanelBackupParser
    domain: str,
    database_name: Optional[str],
    output_dir: str,
    strip_db_prefix: Optional[str] = None,
) -> str:
    """
    Convenience function to transform a cPanel backup for a specific domain.

    Args:
        parser: Initialized CPanelBackupParser
        domain: Domain name to transform
        database_name: Database to include (or None to skip)
        output_dir: Directory for output files
        strip_db_prefix: Optional database prefix to strip

    Returns:
        Path to created restore archive
    """
    os.makedirs(output_dir, exist_ok=True)
    transformer = CPanelTransformer()

    # Extract public_html
    public_html_path = os.path.join(output_dir, 'public_html')
    try:
        parser.extract_public_html(public_html_path)
    except Exception as e:
        logger.warning(f"Could not extract public_html: {e}")
        public_html_path = None

    # Extract database if specified
    database_sql_path = None
    if database_name:
        raw_sql_path = os.path.join(output_dir, f'{database_name}.sql')
        try:
            parser.extract_database(database_name, raw_sql_path)

            # Transform if prefix stripping needed
            if strip_db_prefix:
                database_sql_path = os.path.join(output_dir, 'database.sql')
                transformer.transform_database_sql(
                    raw_sql_path,
                    database_sql_path,
                    strip_prefix=strip_db_prefix,
                )
                os.unlink(raw_sql_path)
            else:
                database_sql_path = raw_sql_path

        except Exception as e:
            logger.warning(f"Could not extract database {database_name}: {e}")

    # Create the restore archive
    archive_path = os.path.join(output_dir, f'{domain.replace(".", "-")}-restore.tar.gz')

    return transformer.create_restore_archive(
        public_html_path=public_html_path,
        database_sql_path=database_sql_path,
        output_path=archive_path,
        metadata={
            'source_domain': domain,
            'source_database': database_name,
        }
    )
