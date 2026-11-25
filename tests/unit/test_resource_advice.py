"""Resource suggestions are local, conservative about uncertainty, and never applied."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from ciclosec.common import resource_advice as advice


def test_cgroup_mount_resolution_and_visible_ancestors(monkeypatch: pytest.MonkeyPatch) -> None:
    files = {
        "/proc/self/cgroup": "0::/tenant/worker\n",
        "/proc/self/mountinfo": (
            "42 1 0:42 /tenant /sys/fs/cgroup\\040test rw - cgroup2 cgroup rw"
        ),
    }
    monkeypatch.setattr(advice, "_read", lambda path: files[path.as_posix()])
    assert [path.as_posix() for path in advice._cgroup_directories()] == [
        "/sys/fs/cgroup test/worker",
        "/sys/fs/cgroup test",
    ]


@pytest.mark.parametrize(
    ("group", "mount"),
    [
        ("0::/tenant/../other", "1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw"),
        ("0::/outside", "1 0 0:1 /tenant /sys/fs/cgroup rw - cgroup2 cgroup rw"),
        ("1:cpu:/", "1 0 0:1 / /sys/fs/cgroup rw - cgroup cgroup rw"),
        ("0::/\n0::/duplicate", "1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw"),
    ],
)
def test_cgroup_resolution_rejects_unverified_membership(
    monkeypatch: pytest.MonkeyPatch, group: str, mount: str
) -> None:
    monkeypatch.setattr(
        advice, "_read", lambda path: group if path.as_posix().endswith("cgroup") else mount
    )
    with pytest.raises(ValueError):
        advice._cgroup_directories()


def test_cgroup_bounds_use_most_restrictive_ancestor(monkeypatch: pytest.MonkeyPatch) -> None:
    files = {
        "child/cpu.max": "200000 100000",
        "parent/cpu.max": "50000 100000",
        "child/memory.max": "1000",
        "child/memory.current": "200",
        "parent/memory.max": "1200",
        "parent/memory.current": "1100",
    }
    monkeypatch.setattr(advice, "_read", lambda path: files[path.as_posix()])
    assert advice._cgroup_bounds([Path("child"), Path("parent")]) == (0.5, 100)


def test_cgroup_unlimited_and_exhausted(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {"cpu.max": "max 100000", "memory.max": "100", "memory.current": "120"}
    monkeypatch.setattr(advice, "_read", lambda path: values[path.name])
    assert advice._cgroup_bounds([Path("group")]) == (None, 0)


def test_v1_resolves_controllers_and_restrictive_ancestors(monkeypatch: pytest.MonkeyPatch) -> None:
    files = {
        "/proc/self/cgroup": "2:cpu,cpuacct:/tenant/scan\n1:memory:/tenant/scan",
        "/proc/self/mountinfo": (
            "1 0 0:1 /tenant /cg/cpu rw - cgroup cgroup rw,cpu,cpuacct\n"
            "2 0 0:2 /tenant /cg/memory rw - cgroup cgroup rw,memory"
        ),
        "/cg/cpu/scan/cpu.cfs_quota_us": "-1",
        "/cg/cpu/scan/cpu.cfs_period_us": "100000",
        "/cg/cpu/cpu.cfs_quota_us": "25000",
        "/cg/cpu/cpu.cfs_period_us": "100000",
        "/cg/memory/scan/memory.limit_in_bytes": "1000",
        "/cg/memory/scan/memory.usage_in_bytes": "100",
        "/cg/memory/memory.limit_in_bytes": "800",
        "/cg/memory/memory.usage_in_bytes": "700",
    }
    monkeypatch.setattr(advice, "_read", lambda path: files[path.as_posix()])
    assert advice._v1_bounds() == (0.25, 100)


def test_v1_fallback_is_used_when_v2_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(advice.sys, "platform", "linux")
    monkeypatch.setattr(advice.os, "sched_getaffinity", lambda _: set(range(4)), raising=False)
    monkeypatch.setattr(advice, "_linux_memory_available", lambda: 4000)
    monkeypatch.setattr(advice, "_cgroup_directories", Mock(side_effect=OSError))
    monkeypatch.setattr(advice, "_v1_bounds", lambda: (0.5, 1000))
    monkeypatch.setattr(Path, "is_dir", lambda _: False)
    report = advice.collect(Path("unused"))
    assert report["resources"]["cpu"]["observed"] == 0.5
    assert report["resources"]["memory"]["observed"] == 1000
    assert "cgroup v1" in str(report["notes"])


@pytest.mark.parametrize(
    ("quota", "period", "limit", "usage"),
    [
        ("-2", "100", "100", "0"),
        ("1", "0", "100", "0"),
        ("-1", "100", "-1", "0"),
        ("-1", "100", "100", "-1"),
        ("broken", "100", "100", "0"),
    ],
)
def test_v1_invalid_values_fail_closed(
    monkeypatch: pytest.MonkeyPatch, quota: str, period: str, limit: str, usage: str
) -> None:
    monkeypatch.setattr(advice, "_v1_directories", lambda _: [Path("group")])
    values = {
        "cpu.cfs_quota_us": quota,
        "cpu.cfs_period_us": period,
        "memory.limit_in_bytes": limit,
        "memory.usage_in_bytes": usage,
    }
    monkeypatch.setattr(advice, "_read", lambda path: values[path.name])
    with pytest.raises(ValueError):
        advice._v1_bounds()


@pytest.mark.parametrize(
    ("cpu", "maximum", "current"),
    [
        ("0 100000", "max", "0"),
        ("100 0", "max", "0"),
        ("broken", "max", "0"),
        ("max 100000", "-1", "0"),
        ("max 100000", "100", "-1"),
        ("max 100000", "100", "bad"),
    ],
)
def test_cgroup_invalid_contents_fail_closed(
    monkeypatch: pytest.MonkeyPatch, cpu: str, maximum: str, current: str
) -> None:
    values = {"cpu.max": cpu, "memory.max": maximum, "memory.current": current}
    monkeypatch.setattr(advice, "_read", lambda path: values[path.name])
    with pytest.raises(ValueError):
        advice._cgroup_bounds([Path("group")])


def test_linux_report_uses_visible_bounds_without_claiming_safety(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(advice.sys, "platform", "linux")
    monkeypatch.setattr(advice.os, "cpu_count", lambda: 8)
    monkeypatch.setattr(advice.os, "sched_getaffinity", lambda _: set(range(4)), raising=False)
    monkeypatch.setattr(advice, "_linux_memory_available", lambda: 4000)
    monkeypatch.setattr(advice, "_cgroup_directories", lambda: [Path("group")])
    monkeypatch.setattr(advice, "_cgroup_bounds", lambda _: (0.5, 1000))
    monkeypatch.setattr(advice.shutil, "disk_usage", lambda _: SimpleNamespace(free=8000))
    monkeypatch.setattr(Path, "is_dir", lambda _: True)
    report = advice.collect(Path("unused"))
    resources = report["resources"]
    assert isinstance(resources, dict)
    assert resources["cpu"]["observed"] == 0.5
    assert resources["cpu"]["suggested_per_scan"] == 0.25
    assert resources["memory"]["suggested_per_scan"] == 250
    assert resources["disk"]["suggested_per_scan"] == 800
    assert all(value["confidence"] == "uncertain" for value in resources.values())
    assert report["enforcement"] == "not_implemented"
    assert "padres ocultos" in str(report["notes"])


@pytest.mark.parametrize("platform", ["linux", "win32", "other"])
def test_partial_failures_and_unverified_containment_are_explicit(
    monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    monkeypatch.setattr(advice.sys, "platform", platform)
    monkeypatch.setattr(advice.os, "cpu_count", lambda: 4)
    monkeypatch.setattr(advice.os, "sched_getaffinity", lambda _: set(range(4)), raising=False)
    monkeypatch.setattr(advice, "_linux_memory_available", lambda: 2048)
    monkeypatch.setattr(advice, "_windows_memory_available", lambda: 2048)
    monkeypatch.setattr(advice, "_cgroup_directories", Mock(side_effect=OSError("secret-sentinel")))
    monkeypatch.setattr(advice, "_v1_bounds", Mock(side_effect=OSError("secret-sentinel")))
    monkeypatch.setattr(Path, "is_dir", lambda _: False)
    report = advice.collect(Path("secret-sentinel"))
    output = json.dumps(report)
    assert "secret-sentinel" not in output
    assert "no verific" in output.lower()
    assert report["resources"]["disk"]["observed"] is None
    assert report["resources"]["disk"]["suggested_per_scan"] is None
    if platform != "other":
        assert report["resources"]["memory"]["suggested_per_scan"] == 512
    assert report["resources"]["cpu"]["confidence"] == "uncertain"


def test_memory_probe_failures_and_zero_values_produce_no_suggestions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(advice.sys, "platform", "linux")
    monkeypatch.setattr(advice.os, "sched_getaffinity", lambda _: set(), raising=False)
    monkeypatch.setattr(advice, "_linux_memory_available", Mock(side_effect=OSError("private")))
    monkeypatch.setattr(advice, "_cgroup_directories", lambda: [Path("group")])
    monkeypatch.setattr(advice, "_cgroup_bounds", lambda _: (None, 0))
    monkeypatch.setattr(Path, "is_dir", lambda _: True)
    monkeypatch.setattr(advice.shutil, "disk_usage", lambda _: SimpleNamespace(free=0))
    report = advice.collect(Path("unused"))
    assert all(item["suggested_per_scan"] is None for item in report["resources"].values())
    assert "private" not in json.dumps(report)


def test_cli_outputs_json_without_loading_django_or_starting_services(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    observed = Mock(return_value={"enforcement": "not_implemented"})
    monkeypatch.setattr(advice, "collect", observed)
    advice.main(["--path", "working-directory"])
    observed.assert_called_once_with(Path("working-directory"))
    assert json.loads(capsys.readouterr().out) == {"enforcement": "not_implemented"}
