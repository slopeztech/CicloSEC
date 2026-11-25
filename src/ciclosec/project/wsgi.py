"""WSGI entry point for CicloSec."""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ciclosec.project.settings")

application = get_wsgi_application()
