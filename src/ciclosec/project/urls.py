"""URL routes for CicloSec."""

from django.contrib import admin
from django.http import HttpResponse, JsonResponse
from django.urls import include, path
from rest_framework.routers import DefaultRouter

from ciclosec.assets.api.views import (
    AssetViewSet,
    ContainerImageViewSet,
    RepositoryViewSet,
)
from ciclosec.findings.api.views import FindingViewSet
from ciclosec.intelligence.api import ManualSyncView
from ciclosec.scans.api.views import ScanRunViewSet

router = DefaultRouter()
router.register("assets", AssetViewSet)
router.register("repositories", RepositoryViewSet)
router.register("container-images", ContainerImageViewSet)
router.register("scans", ScanRunViewSet)
router.register("findings", FindingViewSet)


def _integer_parameter(name: str, minimum: int = 0) -> dict[str, object]:
    return {"name": name, "in": "query", "schema": {"type": "integer", "minimum": minimum}}


def _limit_parameter() -> dict[str, object]:
    return {
        "name": "limit",
        "in": "query",
        "schema": {"type": "integer", "minimum": 1, "maximum": 100},
    }


def openapi_contract(request: object) -> JsonResponse:
    """Return a bounded, versioned contract for current read and review operations."""
    contract = {
        "openapi": "3.0.3",
        "info": {
            "title": "CicloSec API",
            "version": "1.0.0",
            "description": (
                "Authenticated local API. Reading history is read-only; "
                "finding decisions require staff."
            ),
        },
        "servers": [{"url": "/"}],
        "components": {"securitySchemes": {"session": {"type": "cookie", "name": "sessionid"}}},
        "security": [{"session": []}],
        "paths": {
            "/api/assets/": {
                "get": {
                    "summary": "List assets",
                    "parameters": [
                        _limit_parameter(),
                        _integer_parameter("offset"),
                        {
                            "name": "kind",
                            "in": "query",
                            "schema": {"type": "string", "enum": ["repository", "container_image"]},
                        },
                        {
                            "name": "enabled",
                            "in": "query",
                            "schema": {"type": "string", "enum": ["true", "false"]},
                        },
                        {
                            "name": "search",
                            "in": "query",
                            "schema": {"type": "string", "maxLength": 200},
                        },
                    ],
                },
                "post": {"summary": "Create an asset"},
            },
            "/api/scans/": {
                "get": {
                    "summary": "List scans",
                    "parameters": [
                        _limit_parameter(),
                        _integer_parameter("offset"),
                        {
                            "name": "asset",
                            "in": "query",
                            "schema": {"type": "integer", "minimum": 1},
                        },
                        {"name": "status", "in": "query", "schema": {"type": "string"}},
                    ],
                },
                "post": {"summary": "Request an enabled scan"},
            },
            "/api/findings/": {
                "get": {
                    "summary": "List findings",
                    "parameters": [
                        _limit_parameter(),
                        _integer_parameter("offset"),
                        {
                            "name": "asset",
                            "in": "query",
                            "schema": {"type": "integer", "minimum": 1},
                        },
                        {"name": "affected_status", "in": "query", "schema": {"type": "string"}},
                        {"name": "source", "in": "query", "schema": {"type": "string"}},
                        {
                            "name": "search",
                            "in": "query",
                            "schema": {"type": "string", "maxLength": 200},
                        },
                    ],
                }
            },
            "/api/findings/{id}/decision/": {
                "post": {
                    "summary": "Record an administrator finding decision",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        }
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["status", "reason"],
                                    "properties": {
                                        "status": {
                                            "type": "string",
                                            "enum": [
                                                "open",
                                                "assigned",
                                                "accepted_risk",
                                                "false_positive",
                                                "closed",
                                            ],
                                        },
                                        "reason": {
                                            "type": "string",
                                            "minLength": 1,
                                            "maxLength": 4000,
                                        },
                                        "assignee": {"type": "integer", "minimum": 1},
                                    },
                                }
                            }
                        },
                    },
                }
            },
        },
    }
    return JsonResponse(contract)


def api_docs(request: object) -> HttpResponse:
    return HttpResponse(
        """<!doctype html><html lang="es"><head><meta charset="utf-8">
        <title>CicloSec API</title></head><body>
        <h1>CicloSec API</h1>
        <p><a href="/api/openapi.json">Contrato OpenAPI JSON</a></p>
        <p>Ejemplos:</p>
        <pre>GET /api/assets/?limit=50&amp;offset=0
GET /api/scans/?asset=1&amp;status=partial&amp;limit=25&amp;offset=0
GET /api/findings/?asset=1&amp;affected_status=pending_verification&amp;limit=25&amp;offset=0
POST /api/findings/364/decision/
-d '{"status":"false_positive","reason":"Verified test fixture","assignee":1}'
</pre></body></html>""",
        content_type="text/html",
    )


urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("ciclosec.web.urls")),
    path("api/intelligence/sync/", ManualSyncView.as_view(), name="intelligence-sync"),
    path("api/openapi.json", openapi_contract, name="api-openapi"),
    path("api/docs/", api_docs, name="api-docs"),
    path("api/", include(router.urls)),
]
