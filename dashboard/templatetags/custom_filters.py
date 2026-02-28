from django import template
from django.contrib.contenttypes.models import ContentType

register = template.Library()

@register.filter
def get_content_type_id(obj):
    """Get the content type ID for a model instance"""
    if obj:
        content_type = ContentType.objects.get_for_model(obj)
        return content_type.id
    return None

@register.simple_tag
def log_count_for_object(obj, level=None):
    """Get log count for a specific object, optionally filtered by level"""
    from dashboard.models import LogEntry
    from django.contrib.contenttypes.models import ContentType
    
    if not obj:
        return 0
    
    content_type = ContentType.objects.get_for_model(obj)
    logs = LogEntry.objects.filter(content_type=content_type, object_id=obj.pk)
    
    if level:
        logs = logs.filter(level=level)
    
    return logs.count()

@register.inclusion_tag('logging/log_widget.html')
def show_recent_logs(obj, limit=5):
    """Template tag to show recent logs for an object"""
    from dashboard.models import LogEntry
    from django.contrib.contenttypes.models import ContentType
    
    if not obj:
        return {'logs': []}
    
    content_type = ContentType.objects.get_for_model(obj)
    logs = LogEntry.objects.filter(
        content_type=content_type, 
        object_id=obj.pk
    ).order_by('-timestamp')[:limit]
    
    return {'logs': logs, 'object': obj}

@register.filter
def level_badge_class(level):
    """Get Bootstrap badge class for log level"""
    level_classes = {
        'DEBUG': 'secondary',
        'INFO': 'primary',
        'WARNING': 'warning',
        'ERROR': 'danger',
        'CRITICAL': 'danger'
    }
    return level_classes.get(level, 'secondary')

@register.filter
def level_icon(level):
    """Get FontAwesome icon for log level"""
    level_icons = {
        'DEBUG': 'fas fa-bug',
        'INFO': 'fas fa-info-circle',
        'WARNING': 'fas fa-exclamation-triangle',
        'ERROR': 'fas fa-times-circle',
        'CRITICAL': 'fas fa-skull-crossbones'
    }
    return level_icons.get(level, 'fas fa-circle')
