"""
Context processors for the dashboard app.
"""
from dashboard.models import SystemSettings


def system_settings(request):
    """
    Make SystemSettings available in all templates as 'system_settings'.

    This allows templates to access site branding and other system-wide settings.
    """
    return {'system_settings': SystemSettings.get_settings()}
