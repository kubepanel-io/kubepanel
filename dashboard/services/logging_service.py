import logging
from typing import Dict, Any, Optional, Union
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import User
from django.db import models
from dashboard.models import LogEntry

logger = logging.getLogger(__name__)

class KubepanelLogger:
    """
    Centralized logging service for Kubepanel application.
    Provides easy-to-use methods for logging various events with proper user context.
    """
    
    @staticmethod
    def log(
        content_object: models.Model,
        message: str,
        level: str = 'INFO',
        actor: Optional[str] = None,
        user: Optional[User] = None,
        data: Optional[Dict[str, Any]] = None
    ) -> LogEntry:
        """
        Create a log entry for any Django model instance.
        
        Args:
            content_object: The Django model instance this log relates to
            message: Human-readable log message
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            actor: String identifier of the actor (e.g., 'user:alice', 'system', 'cron_job')
            user: Django User instance if available
            data: Additional structured data as JSON
            
        Returns:
            LogEntry: The created log entry
        """
        try:
            # Auto-generate actor if not provided
            if not actor:
                if user:
                    actor = f"user:{user.username}"
                else:
                    actor = "system"
            
            # Validate level
            valid_levels = [choice[0] for choice in LogEntry.LEVEL_CHOICES]
            if level not in valid_levels:
                level = 'INFO'
                logger.warning(f"Invalid log level provided, defaulting to INFO: {level}")
            
            log_entry = LogEntry.objects.create(
                content_object=content_object,
                actor=actor,
                user=user,
                level=level,
                message=message,
                data=data or {}
            )
            
            logger.debug(f"Created log entry {log_entry.id}: {actor} -> {content_object}")
            return log_entry
            
        except Exception as e:
            # Fallback to standard logging if database logging fails
            logger.error(f"Failed to create log entry: {e}")
            logger.log(getattr(logging, level, logging.INFO), f"{actor}: {message}")
            raise
    
    @staticmethod
    def info(content_object: models.Model, message: str, actor: str = None, user: User = None, data: Dict = None) -> LogEntry:
        """Log an INFO level message"""
        return KubepanelLogger.log(content_object, message, 'INFO', actor, user, data)
    
    @staticmethod
    def warning(content_object: models.Model, message: str, actor: str = None, user: User = None, data: Dict = None) -> LogEntry:
        """Log a WARNING level message"""
        return KubepanelLogger.log(content_object, message, 'WARNING', actor, user, data)
    
    @staticmethod
    def error(content_object: models.Model, message: str, actor: str = None, user: User = None, data: Dict = None) -> LogEntry:
        """Log an ERROR level message"""
        return KubepanelLogger.log(content_object, message, 'ERROR', actor, user, data)
    
    @staticmethod
    def critical(content_object: models.Model, message: str, actor: str = None, user: User = None, data: Dict = None) -> LogEntry:
        """Log a CRITICAL level message"""
        return KubepanelLogger.log(content_object, message, 'CRITICAL', actor, user, data)
    
    @staticmethod
    def debug(content_object: models.Model, message: str, actor: str = None, user: User = None, data: Dict = None) -> LogEntry:
        """Log a DEBUG level message"""
        return KubepanelLogger.log(content_object, message, 'DEBUG', actor, user, data)
    
    @staticmethod
    def log_domain_action(domain, action: str, user: User, details: Dict = None) -> LogEntry:
        """
        Convenience method for logging domain-related actions
        
        Args:
            domain: Domain model instance
            action: Action description (e.g., 'created', 'updated', 'deleted', 'started', 'stopped')
            user: User who performed the action
            details: Additional details about the action
        """
        message = f"Domain {action}: {domain.domain_name}"
        data = {"action": action, "domain_id": domain.pk}
        if details:
            data.update(details)
        
        return KubepanelLogger.info(
            content_object=domain,
            message=message,
            user=user,
            data=data
        )
    
    @staticmethod
    def log_mail_action(mail_obj, action: str, user: User, details: Dict = None) -> LogEntry:
        """
        Convenience method for logging mail-related actions
        
        Args:
            mail_obj: MailUser or MailAlias instance
            action: Action description
            user: User who performed the action
            details: Additional details
        """
        if hasattr(mail_obj, 'email'):  # MailUser
            identifier = mail_obj.email
        else:  # MailAlias
            identifier = f"{mail_obj.source} -> {mail_obj.destination}"
        
        message = f"Mail {action}: {identifier}"
        data = {"action": action}
        if details:
            data.update(details)
        
        return KubepanelLogger.info(
            content_object=mail_obj,
            message=message,
            user=user,
            data=data
        )
    
    @staticmethod
    def log_dns_action(dns_obj, action: str, user: User, details: Dict = None) -> LogEntry:
        """
        Convenience method for logging DNS-related actions
        
        Args:
            dns_obj: DNSRecord or DNSZone instance
            action: Action description
            user: User who performed the action
            details: Additional details
        """
        if hasattr(dns_obj, 'record_type'):  # DNSRecord
            identifier = f"{dns_obj.record_type} {dns_obj.name} -> {dns_obj.content}"
        else:  # DNSZone
            identifier = dns_obj.name
        
        message = f"DNS {action}: {identifier}"
        data = {"action": action}
        if details:
            data.update(details)
        
        return KubepanelLogger.info(
            content_object=dns_obj,
            message=message,
            user=user,
            data=data
        )
    
    @staticmethod
    def log_system_event(message: str, level: str = 'INFO', actor: str = 'system', user: User = None, data: Dict = None) -> Optional[LogEntry]:
        """
        Log system-wide events. Uses the User as the content_object since
        system events typically relate to user actions (login, logout, etc.).

        Args:
            message: Log message
            level: Log level
            actor: Actor identifier
            user: User associated with the event (used as content_object)
            data: Additional data
        """
        try:
            if user:
                # Use the user as the content_object
                return KubepanelLogger.log(
                    content_object=user,
                    message=message,
                    level=level,
                    actor=actor,
                    user=user,
                    data=data
                )
            else:
                # No user provided - just use standard logging
                logger.log(getattr(logging, level, logging.INFO), f"{actor}: {message}")
                return None
        except Exception as e:
            # Fallback to standard logging
            logger.error(f"Failed to create system log entry: {e}")
            logger.log(getattr(logging, level, logging.INFO), f"{actor}: {message}")
            raise

class LogQueryManager:
    """
    Helper class for querying log entries with user permissions in mind.
    """
    
    @staticmethod
    def get_user_logs(user: User, limit: int = None) -> models.QuerySet:
        """
        Get log entries that a user should be able to see.
        
        Args:
            user: Django User instance
            limit: Maximum number of entries to return (None for no limit)
            
        Returns:
            QuerySet of LogEntry objects
        """
        if user.is_superuser:
            # Superusers can see all logs
            queryset = LogEntry.objects.all().order_by('-timestamp')
        else:
            # Regular users can only see logs for objects they own/have access to
            queryset = LogEntry.objects.filter(user=user).order_by('-timestamp')
        
        # Apply limit only if specified and return the queryset (not sliced)
        if limit:
            # Don't slice here, let the view handle pagination
            pass
            
        return queryset
    
    @staticmethod
    def get_object_logs(content_object: models.Model, user: User = None) -> models.QuerySet:
        """
        Get all log entries for a specific object.
        
        Args:
            content_object: The Django model instance
            user: User requesting the logs (for permission checking)
            
        Returns:
            QuerySet of LogEntry objects
        """
        content_type = ContentType.objects.get_for_model(content_object)
        logs = LogEntry.objects.filter(
            content_type=content_type,
            object_id=content_object.pk
        ).order_by('-timestamp')
        
        # Apply user permissions if specified
        if user and not user.is_superuser:
            # For regular users, filter to only show logs they should see
            # This depends on your business logic
            if hasattr(content_object, 'owner') and content_object.owner != user:
                return LogEntry.objects.none()
        
        return logs
    
    @staticmethod
    def get_logs_by_level(level: str, user: User, limit: int = 100) -> models.QuerySet:
        """Get logs filtered by level with user permissions"""
        base_query = LogQueryManager.get_user_logs(user)
        filtered_query = base_query.filter(level=level)
        return filtered_query[:limit] if limit else filtered_query
    
    @staticmethod
    def get_recent_errors(user: User, limit: int = 50) -> models.QuerySet:
        """Get recent error and critical logs"""
        base_query = LogQueryManager.get_user_logs(user)
        filtered_query = base_query.filter(level__in=['ERROR', 'CRITICAL'])
        return filtered_query[:limit] if limit else filtered_query
