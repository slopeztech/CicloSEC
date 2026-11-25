"""Routes for the server-rendered dashboard and its API."""

from django.contrib.auth import views as auth_views
from django.urls import path

from ciclosec.web import pages
from ciclosec.web.api import DashboardSummaryView
from ciclosec.web.views import dashboard

urlpatterns = [
    path(
        "accounts/login/",
        auth_views.LoginView.as_view(
            template_name="web/login.html",
            redirect_authenticated_user=True,
        ),
        name="login",
    ),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("api/dashboard/", DashboardSummaryView.as_view(), name="api-dashboard"),
    path("", dashboard, name="dashboard"),
    path("assets/", pages.assets, name="assets"),
    path("assets/new/", pages.asset_edit, name="asset-create"),
    path("assets/<int:pk>/", pages.asset_detail, name="web-asset-detail"),
    path("assets/<int:pk>/edit/", pages.asset_edit, name="asset-edit"),
    path("assets/<int:pk>/scan/", pages.request_scan, name="request-scan"),
    path("assets/<int:pk>/schedule/", pages.change_scan_schedule, name="change-scan-schedule"),
    path("findings/", pages.findings, name="findings"),
    path("findings/<int:pk>/", pages.finding_detail, name="web-finding-detail"),
    path("findings/<int:pk>/review/", pages.review_finding_view, name="review-finding"),
    path("sbom/", pages.sbom, name="sbom"),
    path("history/", pages.history, name="history"),
    path("history/<int:pk>/", pages.scan_detail, name="web-scan-detail"),
    path("history/<int:pk>/cancel/", pages.cancel_queued_scan, name="cancel-queued-scan"),
    path("intelligence/", pages.intelligence, name="intelligence"),
    path("intelligence/update/", pages.request_intelligence_update, name="intelligence-update"),
    path("integrations/", pages.integrations, name="integrations"),
    path("settings/", pages.configuration, name="settings"),
]
