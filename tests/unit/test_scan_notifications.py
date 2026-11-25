"""Console notifications for terminal scan outcomes."""

import logging
from types import SimpleNamespace

import pytest
from django.conf import settings

from ciclosec.common.config import NotificationChannelConfig
from ciclosec.scanners import tasks
from ciclosec.scanners.services import ScanAlreadyClaimed
from ciclosec.scans.models import ScanRun

pytestmark = pytest.mark.usefixtures("configuration_state")


class _FindingQuery:
    def count(self) -> int:
        return 3


class _FindingManager:
    def filter(self, *, scan_run: object) -> _FindingQuery:
        return _FindingQuery()


def _scan(status: str) -> SimpleNamespace:
    return SimpleNamespace(
        pk=42,
        status=status,
        asset=SimpleNamespace(name="private-repository"),
        error_summary="private-error",
    )


def _use_fake_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        tasks,
        "Finding",
        SimpleNamespace(objects=_FindingManager()),
    )


@pytest.mark.parametrize(
    "status",
    [
        ScanRun.Status.SUCCEEDED,
        ScanRun.Status.PARTIAL,
        ScanRun.Status.FAILED,
        ScanRun.Status.CANCELLED,
    ],
)
def test_console_notification_is_deduplicated_and_contains_only_safe_summary(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    status: str,
) -> None:
    caplog.set_level(logging.INFO, logger="ciclosec.scanners.tasks")
    _use_fake_findings(monkeypatch)
    monkeypatch.setattr(settings.CICLOSEC_CONFIG.notifications, "enabled", True)
    monkeypatch.setattr(
        settings.CICLOSEC_CONFIG.notifications,
        "channels",
        [NotificationChannelConfig(type="console"), NotificationChannelConfig(type="console")],
    )
    scan = _scan(status)

    result = tasks._run_scan(object(), scan.pk, lambda _scan_id: scan)

    def duplicate(_scan_id: int) -> ScanRun:
        raise ScanAlreadyClaimed(scan)

    duplicate_result = tasks._run_scan(object(), scan.pk, duplicate)
    notifications = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("scan_finished ")
    ]

    assert result["status"] == status
    assert result["finding_count"] == 3
    assert duplicate_result["disposition"] == "already_claimed"
    assert notifications == [f"scan_finished scan_id=42 status={status} finding_count=3"]
    assert "private-repository" not in notifications[0]
    assert "private-error" not in notifications[0]


@pytest.mark.parametrize(
    ("enabled", "channels"),
    [
        (False, [NotificationChannelConfig(type="console")]),
        (True, []),
    ],
)
def test_notification_opt_out_does_not_change_scan_result(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    enabled: bool,
    channels: list[NotificationChannelConfig],
) -> None:
    caplog.set_level(logging.INFO, logger="ciclosec.scanners.tasks")
    _use_fake_findings(monkeypatch)
    monkeypatch.setattr(settings.CICLOSEC_CONFIG.notifications, "enabled", enabled)
    monkeypatch.setattr(settings.CICLOSEC_CONFIG.notifications, "channels", channels)
    scan = _scan(ScanRun.Status.PARTIAL)

    result = tasks._run_scan(object(), scan.pk, lambda _scan_id: scan)

    assert result["status"] == ScanRun.Status.PARTIAL
    assert not any(record.getMessage().startswith("scan_finished ") for record in caplog.records)
