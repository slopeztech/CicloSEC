"""Django application configuration for the local web interface."""

from django.apps import AppConfig


class WebConfig(AppConfig):
    """Configure the CicloSec web interface application."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "ciclosec.web"
