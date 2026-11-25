"""Django settings for the local CicloSec application."""

from __future__ import annotations

import os
from pathlib import Path

import dj_database_url
from dotenv import load_dotenv

from ciclosec.common.config import (
    ConfigurationError,
    load_config,
    resolve_environment_value,
)

BASE_DIR = Path(__file__).resolve().parents[3]
load_dotenv(BASE_DIR / ".env")

config_path = Path(
    os.environ.get(
        "CICLOSEC_CONFIG_PATH",
        str(BASE_DIR / "config" / "ciclosec.yaml"),
    )
)
CICLOSEC_CONFIG = load_config(config_path)
SECRET_KEY = resolve_environment_value("CICLOSEC_DJANGO_SECRET_KEY")
DEBUG = CICLOSEC_CONFIG.application.environment == "local"
ALLOWED_HOSTS = ["localhost", "127.0.0.1"]

database_url = resolve_environment_value(CICLOSEC_CONFIG.database.url_env)
celery_broker_url = resolve_environment_value(CICLOSEC_CONFIG.tasks.broker_url_env)
celery_result_backend_url = resolve_environment_value(CICLOSEC_CONFIG.tasks.result_backend_url_env)

try:
    DATABASES = {
        "default": dj_database_url.parse(
            database_url,
            conn_max_age=60,
            conn_health_checks=True,
        )
    }
except (TypeError, ValueError):
    raise ConfigurationError(
        "Database URL is invalid; check the configured environment variable"
    ) from None

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "ciclosec.common",
    "ciclosec.assets.apps.AssetsConfig",
    "ciclosec.scans.apps.ScansConfig",
    "ciclosec.inventory.apps.InventoryConfig",
    "ciclosec.intelligence.apps.IntelligenceConfig",
    "ciclosec.findings.apps.FindingsConfig",
    "ciclosec.web.apps.WebConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "ciclosec.project.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    }
]
WSGI_APPLICATION = "ciclosec.project.wsgi.application"
ASGI_APPLICATION = "ciclosec.project.asgi.application"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LANGUAGE_CODE = "es-es"
TIME_ZONE = CICLOSEC_CONFIG.application.timezone
USE_I18N = True
USE_TZ = True
STATIC_URL = "static/"

REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
}

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "login"

CELERY_BROKER_URL = celery_broker_url
CELERY_RESULT_BACKEND = celery_result_backend_url
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_ACKS_LATE = True
