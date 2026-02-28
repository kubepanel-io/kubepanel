import json
from django.core.management.base import BaseCommand, CommandError
from django.apps import apps
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import User
from dashboard.models import LogEntry

class Command(BaseCommand):
    help = "Create a LogEntry for any model instance by lookup fields"

    def add_arguments(self, parser):
        parser.add_argument(
            '--model',
            required=True,
            help="Target model in format 'app_label.model_name'"
        )
        parser.add_argument(
            '--lookup',
            action='append',
            required=True,
            help="Field lookup in form field=value; can be repeated"
        )
        parser.add_argument(
            '--actor',
            required=True,
            help="Actor identifier, e.g. 'system:cron_job' or 'user:alice'"
        )
        parser.add_argument(
            '--message',
            required=True,
            help="Log message"
        )
        parser.add_argument(
            '--user',
            type=int,
            help="Optional User ID to link"
        )
        parser.add_argument(
            '--level',
            choices=[choice[0] for choice in LogEntry.LEVEL_CHOICES],
            default='INFO',
            help="Log level"
        )
        parser.add_argument(
            '--data',
            help="Optional JSON string with extra data"
        )

    def handle(self, *args, **options):
        model_label = options['model']
        try:
            app_label, model_name = model_label.split('.')
        except ValueError:
            raise CommandError("`--model` must be in format app_label.model_name")

        Model = apps.get_model(app_label, model_name)
        if Model is None:
            raise CommandError(f"Model '{model_label}' not found")

        lookup_dict = {}
        for lookup in options['lookup']:
            if '=' not in lookup:
                raise CommandError(f"Invalid --lookup format '{lookup}', expected field=value")
            field, value = lookup.split('=', 1)
            lookup_dict[field] = value

        try:
            obj = Model.objects.get(**lookup_dict)
        except Model.DoesNotExist:
            raise CommandError(f"No {model_label} found matching {lookup_dict}")
        except Model.MultipleObjectsReturned:
            raise CommandError(f"Multiple {model_label} objects found matching {lookup_dict}")

        ct = ContentType.objects.get_for_model(Model)
        kwargs = {
            'content_type': ct,
            'object_id': obj.pk,
            'actor': options['actor'],
            'level': options['level'],
            'message': options['message'],
        }

        if options.get('user') is not None:
            try:
                kwargs['user'] = User.objects.get(pk=options['user'])
            except User.DoesNotExist:
                raise CommandError(f"User with ID {options['user']} does not exist")

        if options.get('data'):
            try:
                kwargs['data'] = json.loads(options['data'])
            except json.JSONDecodeError as e:
                raise CommandError(f"Invalid JSON for --data: {e}")

        entry = LogEntry.objects.create(**kwargs)
        self.stdout.write(
            self.style.SUCCESS(
                f"Created LogEntry {entry.pk} for {model_label} {lookup_dict}"
            )
        )

