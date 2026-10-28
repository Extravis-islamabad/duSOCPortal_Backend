from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("tenant", "0208_dufortisoarincidentmodel_ticket_id"),
    ]

    operations = [
        migrations.AddField(
            model_name="dufortisoartenants",
            name="alerts_synced_until",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
