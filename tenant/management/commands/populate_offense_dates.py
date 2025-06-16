from datetime import datetime

from django.core.management.base import BaseCommand

from tenant.models import IBMQradarAssests  # Adjust if needed


class Command(BaseCommand):
    help = "Update converted date fields in IBMQradarAssests"

    def handle(self, *args, **kwargs):
        def convert(ts_str):
            try:
                return datetime.utcfromtimestamp(int(ts_str) / 1000).date()
            except Exception:
                return None

        updated_count = 0

        for asset in IBMQradarAssests.objects.all():
            updated = False

            c = convert(asset.creation_date)
            m = convert(asset.modified_date)
            last_e = convert(asset.last_event_time)

            if c and asset.creation_date_converted != c:
                asset.creation_date_converted = c
                updated = True
            if m and asset.modified_date_converted != m:
                asset.modified_date_converted = m
                updated = True
            if last_e and asset.last_event_date_converted != last_e:
                asset.last_event_date_converted = last_e
                updated = True

            if updated:
                asset.save()
                updated_count += 1

        self.stdout.write(self.style.SUCCESS(f"Updated {updated_count} assets."))
