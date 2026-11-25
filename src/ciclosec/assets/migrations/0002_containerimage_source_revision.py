from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("assets", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="containerimage",
            name="source_revision",
            field=models.PositiveBigIntegerField(default=0),
        ),
    ]
