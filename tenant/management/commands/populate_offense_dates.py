from datetime import datetime

from django.core.management.base import BaseCommand

from tenant.models import IBMQradarOffense


class Command(BaseCommand):
    help = "Populate *_date fields for IBMQradarOffense model"

    def handle(self, *args, **kwargs):
        offenses = IBMQradarOffense.objects.all()
        updated = 0
        for offense in offenses:
            try:
                if offense.start_time:
                    offense.start_date = datetime.utcfromtimestamp(
                        offense.start_time / 1000
                    ).date()
                if offense.last_updated_time:
                    offense.last_updated_date = datetime.utcfromtimestamp(
                        offense.last_updated_time / 1000
                    ).date()
                if offense.last_persisted_time:
                    offense.last_persisted_date = datetime.utcfromtimestamp(
                        offense.last_persisted_time / 1000
                    ).date()
                if offense.first_persisted_time:
                    offense.first_persisted_date = datetime.utcfromtimestamp(
                        offense.first_persisted_time / 1000
                    ).date()
                offense.save()
                updated += 1
            except Exception as e:
                self.stderr.write(f"Error processing offense {offense.id}: {e}")
        self.stdout.write(self.style.SUCCESS(f"Updated {updated} offenses."))
