"""ASGI entry point for CicloSec."""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ciclosec.project.settings")

application = get_asgi_application()
