"""Django application configuration for findings."""

from django.apps import AppConfig


class FindingsConfig(AppConfig):
    """Configure the findings application."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "ciclosec.findings"
