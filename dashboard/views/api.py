"""
API views for AJAX endpoints.
"""
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required

from dashboard.models import WorkloadType, WorkloadVersion


@login_required
def get_workload_versions(request, type_id):
    """
    Return workload versions for a given type as JSON.
    Used by the add_domain form for dynamic version dropdown loading.
    """
    try:
        workload_type = WorkloadType.objects.get(pk=type_id, is_active=True)
    except WorkloadType.DoesNotExist:
        return JsonResponse({'error': 'Workload type not found'}, status=404)

    versions = WorkloadVersion.objects.filter(
        workload_type=workload_type,
        is_active=True
    ).order_by('display_order', 'version')

    data = {
        'type': {
            'id': workload_type.pk,
            'name': workload_type.name,
            'slug': workload_type.slug,
        },
        'versions': [
            {
                'id': v.pk,
                'version': v.version,
                'label': f"{workload_type.name} {v.version}",
                'is_default': v.is_default,
            }
            for v in versions
        ]
    }

    return JsonResponse(data)


@login_required
def get_workload_types(request):
    """
    Return all active workload types as JSON.
    Used for initializing the workload type dropdown.
    """
    types = WorkloadType.objects.filter(is_active=True).order_by('display_order', 'name')

    # Find the default version to determine default type
    default_version = WorkloadVersion.objects.filter(is_default=True, is_active=True).first()
    default_type_id = default_version.workload_type_id if default_version else None

    data = {
        'types': [
            {
                'id': t.pk,
                'name': t.name,
                'slug': t.slug,
                'icon': t.icon,
                'is_default': t.pk == default_type_id,
            }
            for t in types
        ],
        'default_type_id': default_type_id,
    }

    return JsonResponse(data)
