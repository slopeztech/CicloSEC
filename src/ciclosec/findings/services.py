"""Reevaluate persisted findings against synchronized intelligence."""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping
from typing import Any

from django.db import transaction
from django.db.models import Prefetch, QuerySet
from django.utils import timezone
from packageurl import PackageURL

from ciclosec.assets.services import scan_source_status_for_asset
from ciclosec.findings.models import (
    Finding,
    FindingDecision,
    FindingDecisionEvent,
    RiskAssessment,
)
from ciclosec.intelligence.merging import MergeConflict, lock_alias_roots, root_id
from ciclosec.intelligence.models import (
    AdvisoryRecord,
    IntelligenceSource,
    Vulnerability,
    VulnerabilityAlias,
)

RISK_POLICY_VERSION = "risk-v1"
MAX_CORRELATION_EVIDENCE = 50
_NUMERIC_VERSION = re.compile(r"^[vV]?([0-9]+(?:\.[0-9]+)*)(?:\+[A-Za-z0-9.-]+)?$")
_VERSION_CLAUSE = re.compile(r"^(<=|>=|==|!=|=|<|>)\s*(\S+)$")
_ECOSYSTEMS = {
    "alpine": "alpine",
    "arch": "arch",
    "cargo": "cargo",
    "composer": "composer",
    "crates.io": "cargo",
    "debian": "deb",
    "deb": "deb",
    "erlang": "hex",
    "gem": "gem",
    "go": "golang",
    "golang": "golang",
    "hex": "hex",
    "maven": "maven",
    "npm": "npm",
    "nuget": "nuget",
    "packagist": "composer",
    "pip": "pypi",
    "pypi": "pypi",
    "python": "pypi",
    "rubygems": "gem",
    "rust": "cargo",
    "swift": "swift",
    "swifturl": "swift",
    "ubuntu": "deb",
    "pub": "pub",
}


class CorrelationError(RuntimeError):
    """Persisted intelligence or finding data cannot be correlated safely."""


def _numeric_version(value: str) -> tuple[int, ...] | None:
    match = _NUMERIC_VERSION.fullmatch(value.strip())
    if match is None:
        return None
    parts = tuple(int(part) for part in match.group(1).split("."))
    while len(parts) > 1 and parts[-1] == 0:
        parts = parts[:-1]
    return parts


def _compare_versions(left: str, right: str) -> int | None:
    left_parts = _numeric_version(left)
    right_parts = _numeric_version(right)
    if left_parts is None or right_parts is None:
        return None
    width = max(len(left_parts), len(right_parts))
    left_parts += (0,) * (width - len(left_parts))
    right_parts += (0,) * (width - len(right_parts))
    return (left_parts > right_parts) - (left_parts < right_parts)


def _evaluate_specifier(version: str, expression: str) -> bool | None:
    clauses = expression.split(",")
    if not clauses or any(not clause.strip() for clause in clauses):
        return None
    for clause in clauses:
        match = _VERSION_CLAUSE.fullmatch(clause.strip())
        if match is None:
            return None
        operator, boundary = match.groups()
        comparison = _compare_versions(version, boundary)
        if comparison is None:
            return None
        matches = {
            "<": comparison < 0,
            "<=": comparison <= 0,
            "=": comparison == 0,
            "==": comparison == 0,
            "!=": comparison != 0,
            ">": comparison > 0,
            ">=": comparison >= 0,
        }[operator]
        if not matches:
            return False
    return True


def _evaluate_osv_range(version: str, affected_range: Mapping[str, Any]) -> bool | None:
    range_type = affected_range.get("type")
    events = affected_range.get("events")
    version_parts = _numeric_version(version)
    if (
        range_type != "SEMVER"
        or not isinstance(events, list)
        or not events
        or version_parts is None
    ):
        return None

    interval_open = False
    lower_bound: tuple[int, ...] | None = None
    saw_interval = False
    for event in events:
        if not isinstance(event, dict):
            return None
        event_keys = [
            key for key in ("introduced", "fixed", "last_affected", "limit") if key in event
        ]
        if len(event_keys) != 1:
            return None
        event_name = event_keys[0]
        event_version = event[event_name]
        if not isinstance(event_version, str):
            return None
        if event_name == "introduced":
            if interval_open:
                return None
            interval_open = True
            saw_interval = True
            lower_bound = None if event_version == "0" else _numeric_version(event_version)
            if event_version != "0" and lower_bound is None:
                return None
            continue
        if event_name == "limit" or not interval_open:
            return None
        upper_bound = _numeric_version(event_version)
        if upper_bound is None:
            return None
        lower_matches = lower_bound is None or version_parts >= lower_bound
        inclusive_upper = event_name == "last_affected"
        upper_matches = (
            version_parts <= upper_bound if inclusive_upper else version_parts < upper_bound
        )
        if lower_matches and upper_matches:
            return True
        interval_open = False
        lower_bound = None

    if interval_open:
        return lower_bound is None or version_parts >= lower_bound
    return False if saw_interval else None


def _evaluate_osv_affected(version: str, affected: Mapping[str, Any]) -> tuple[bool | None, str]:
    versions = affected.get("versions", [])
    ranges = affected.get("ranges", [])
    if not isinstance(versions, list) or not isinstance(ranges, list):
        return None, Finding.Confidence.LOW
    if any(not isinstance(item, str) for item in versions):
        return None, Finding.Confidence.LOW
    if version in versions:
        return True, Finding.Confidence.HIGH

    range_results: list[bool | None] = []
    for item in ranges:
        if not isinstance(item, dict):
            range_results.append(None)
            continue
        range_results.append(_evaluate_osv_range(version, item))
    if any(result is True for result in range_results):
        return True, Finding.Confidence.MEDIUM
    if range_results and all(result is False for result in range_results):
        return False, Finding.Confidence.MEDIUM
    if versions and not ranges:
        return False, Finding.Confidence.HIGH
    return None, Finding.Confidence.LOW


def _canonical_ecosystem(value: str) -> str:
    normalized = value.strip().casefold()
    return _ECOSYSTEMS.get(normalized, "")


def _canonical_package_name(value: str, ecosystem: str) -> str:
    normalized = value.strip()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", normalized).casefold()
    return normalized.casefold()


def _package_identity_matches(
    finding_ecosystem: str,
    finding_name: str,
    advisory_ecosystem: str,
    advisory_name: str,
) -> bool | None:
    local_ecosystem = _canonical_ecosystem(finding_ecosystem)
    source_ecosystem = _canonical_ecosystem(advisory_ecosystem)
    if not local_ecosystem or not source_ecosystem:
        return None
    if local_ecosystem != source_ecosystem:
        return False
    return _canonical_package_name(
        finding_name,
        local_ecosystem,
    ) == _canonical_package_name(advisory_name, source_ecosystem)


def _finding_package(finding: Finding) -> tuple[str, str, str]:
    if finding.component_occurrence is not None:
        occurrence = finding.component_occurrence
        return (
            occurrence.component.ecosystem,
            occurrence.component.name,
            occurrence.version or finding.package_version,
        )
    evidence = finding.evidence
    if not isinstance(evidence, dict):
        raise CorrelationError("Finding evidence is not a JSON object")
    ecosystem = evidence.get("ecosystem", "")
    package_url = evidence.get("package_url")
    if not isinstance(ecosystem, str):
        ecosystem = ""
    if not ecosystem and isinstance(package_url, str) and package_url:
        try:
            ecosystem = PackageURL.from_string(package_url).type
        except ValueError:
            ecosystem = ""
    return ecosystem, finding.package_name, finding.package_version


def _resolve_finding_vulnerability(finding: Finding) -> Vulnerability | None:
    if finding.vulnerability_id is not None:
        return finding.vulnerability
    evidence = finding.evidence
    if not isinstance(evidence, dict):
        raise CorrelationError("Finding evidence is not a JSON object")
    identifiers = {finding.external_id} if finding.external_id else set()
    aliases = evidence.get("aliases", [])
    if aliases is not None:
        if not isinstance(aliases, list) or any(not isinstance(item, str) for item in aliases):
            raise CorrelationError("Finding aliases are invalid")
        identifiers.update(item for item in aliases if item)
    if not identifiers:
        return None
    matches = list(
        VulnerabilityAlias.objects.filter(identifier__in=identifiers).select_related(
            "vulnerability"
        )
    )
    try:
        lock_alias_roots(matches)
    except MergeConflict as error:
        raise CorrelationError(str(error)) from error
    vulnerability_ids = {root_id(item.vulnerability) for item in matches}
    if len(vulnerability_ids) > 1:
        raise CorrelationError("Finding identifiers map to conflicting vulnerabilities")
    return matches[0].vulnerability if matches else None


def _package_scopes(
    records: list[AdvisoryRecord],
) -> tuple[list[tuple[AdvisoryRecord, str, str, Mapping[str, Any]]], bool]:
    scopes: list[tuple[AdvisoryRecord, str, str, Mapping[str, Any]]] = []
    unknown_scope = False
    for record in records:
        raw_record = record.raw_record
        if not isinstance(raw_record, dict):
            raise CorrelationError("Advisory record payload is not a JSON object")
        if record.provider == AdvisoryRecord.Provider.OSV:
            affected_items = raw_record.get("affected")
            if not isinstance(affected_items, list):
                unknown_scope = True
                continue
            for affected in affected_items:
                if not isinstance(affected, dict):
                    unknown_scope = True
                    continue
                package = affected.get("package")
                if not isinstance(package, dict):
                    unknown_scope = True
                    continue
                ecosystem = package.get("ecosystem")
                name = package.get("name")
                if (
                    not isinstance(ecosystem, str)
                    or not ecosystem
                    or not isinstance(name, str)
                    or not name
                ):
                    unknown_scope = True
                    continue
                scopes.append((record, ecosystem, name, affected))
        elif record.provider == AdvisoryRecord.Provider.GITHUB:
            vulnerabilities = raw_record.get("vulnerabilities")
            if not isinstance(vulnerabilities, list):
                unknown_scope = True
                continue
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    unknown_scope = True
                    continue
                package = vulnerability.get("package")
                if not isinstance(package, dict):
                    unknown_scope = True
                    continue
                ecosystem = package.get("ecosystem")
                name = package.get("name")
                if (
                    not isinstance(ecosystem, str)
                    or not ecosystem
                    or not isinstance(name, str)
                    or not name
                ):
                    unknown_scope = True
                    continue
                scopes.append((record, ecosystem, name, vulnerability))
    return scopes, unknown_scope


def _scope_version_result(
    record: AdvisoryRecord,
    version: str,
    scope: Mapping[str, Any],
) -> tuple[bool | None, str]:
    if not version:
        return None, Finding.Confidence.LOW
    if record.provider == AdvisoryRecord.Provider.OSV:
        return _evaluate_osv_affected(version, scope)
    expression = scope.get("vulnerable_version_range")
    if not isinstance(expression, str) or not expression:
        return None, Finding.Confidence.LOW
    result = _evaluate_specifier(version, expression)
    return result, Finding.Confidence.MEDIUM if result is not None else Finding.Confidence.LOW


def _evaluate_applicability(
    finding: Finding,
    records: list[AdvisoryRecord],
    source_statuses: Mapping[str, str],
) -> tuple[str, str, list[dict[str, Any]]]:
    if finding.kind == Finding.Kind.SECRET:
        return (
            Finding.AffectedStatus.NOT_APPLICABLE,
            Finding.Confidence.HIGH,
            [],
        )
    if finding.vulnerability is None:
        return (
            Finding.AffectedStatus.PENDING_VERIFICATION,
            Finding.Confidence.UNKNOWN,
            [],
        )

    scopes, unknown_scope = _package_scopes(records)
    if not scopes:
        status = (
            Finding.AffectedStatus.POTENTIAL
            if unknown_scope
            else Finding.AffectedStatus.PENDING_VERIFICATION
        )
        confidence = Finding.Confidence.LOW if unknown_scope else Finding.Confidence.UNKNOWN
        return status, confidence, []

    local_ecosystem, local_name, local_version = _finding_package(finding)
    if not local_name or not _canonical_ecosystem(local_ecosystem):
        return Finding.AffectedStatus.POTENTIAL, Finding.Confidence.LOW, []

    matched_results: list[tuple[bool | None, str]] = []
    evidence: list[dict[str, Any]] = []
    unresolved_identity = unknown_scope
    for record, ecosystem, package_name, scope in scopes:
        identity_matches = _package_identity_matches(
            local_ecosystem,
            local_name,
            ecosystem,
            package_name,
        )
        version_result: bool | None = None
        version_confidence: str = Finding.Confidence.LOW
        if identity_matches is True:
            version_result, version_confidence = _scope_version_result(
                record,
                local_version,
                scope,
            )
            matched_results.append((version_result, version_confidence))
        elif identity_matches is None:
            unresolved_identity = True
        if len(evidence) < MAX_CORRELATION_EVIDENCE:
            evidence.append(
                {
                    "provider": record.provider,
                    "advisory_id": record.external_id,
                    "source_status": source_statuses.get(
                        record.provider,
                        IntelligenceSource.Status.UNKNOWN,
                    ),
                    "package": package_name,
                    "ecosystem": ecosystem,
                    "package_matches": identity_matches,
                    "version_result": version_result,
                }
            )

    if matched_results:
        if any(result is True for result, _ in matched_results):
            confidence = (
                Finding.Confidence.HIGH
                if any(
                    result is True and level == Finding.Confidence.HIGH
                    for result, level in matched_results
                )
                else Finding.Confidence.MEDIUM
            )
            return Finding.AffectedStatus.CONFIRMED, confidence, evidence
        if any(result is None for result, _ in matched_results):
            return Finding.AffectedStatus.POTENTIAL, Finding.Confidence.LOW, evidence
        confidence = (
            Finding.Confidence.HIGH
            if all(level == Finding.Confidence.HIGH for _, level in matched_results)
            else Finding.Confidence.MEDIUM
        )
        return Finding.AffectedStatus.NOT_AFFECTED, confidence, evidence
    if unresolved_identity:
        return Finding.AffectedStatus.POTENTIAL, Finding.Confidence.LOW, evidence
    return Finding.AffectedStatus.NOT_APPLICABLE, Finding.Confidence.HIGH, evidence


def _validated_score(value: Any, *, signal_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CorrelationError(f"{signal_name} score is invalid")
    score = float(value)
    if not math.isfinite(score) or not 0 <= score <= 10:
        raise CorrelationError(f"{signal_name} score is outside the valid range")
    return score


def _cvss_scores(record: AdvisoryRecord) -> list[float]:
    raw_record = record.raw_record
    if not isinstance(raw_record, dict):
        raise CorrelationError("Advisory record payload is not a JSON object")
    if record.provider == AdvisoryRecord.Provider.NVD:
        metrics = raw_record.get("metrics", {})
        if not isinstance(metrics, dict):
            raise CorrelationError("NVD CVSS metrics are invalid")
        scores: list[float] = []
        for entries in metrics.values():
            if not isinstance(entries, list):
                raise CorrelationError("NVD CVSS metric list is invalid")
            for entry in entries:
                if not isinstance(entry, dict):
                    raise CorrelationError("NVD CVSS metric is invalid")
                cvss_data = entry.get("cvssData")
                if not isinstance(cvss_data, dict):
                    raise CorrelationError("NVD CVSS data is invalid")
                score = cvss_data.get("baseScore")
                if score is not None:
                    scores.append(_validated_score(score, signal_name="NVD CVSS"))
        return scores
    if record.provider == AdvisoryRecord.Provider.GITHUB:
        metrics = raw_record.get("cvss_severities", {})
        if not isinstance(metrics, dict):
            raise CorrelationError("GitHub CVSS metrics are invalid")
        scores = []
        for metric in metrics.values():
            if not isinstance(metric, dict):
                raise CorrelationError("GitHub CVSS metric is invalid")
            score = metric.get("score")
            if score is not None:
                scores.append(_validated_score(score, signal_name="GitHub CVSS"))
        return scores
    return []


def _risk_assessment(
    finding: Finding,
    records: list[AdvisoryRecord],
    affected_status: str,
    source_statuses: Mapping[str, str],
) -> dict[str, Any]:
    source_freshness = {
        provider: source_statuses.get(provider, IntelligenceSource.Status.UNKNOWN)
        for provider in AdvisoryRecord.Provider.values
    }
    freshness_note = (
        "Source freshness: "
        + ", ".join(f"{provider}={status}" for provider, status in sorted(source_freshness.items()))
        + "."
    )
    signals: list[dict[str, Any]] = []
    cvss_records = [(record, score) for record in records for score in _cvss_scores(record)]
    if cvss_records:
        record, cvss_score = max(cvss_records, key=lambda item: item[1])
        signals.append(
            {
                "name": "cvss",
                "value": cvss_score,
                "points": round(cvss_score * 4, 2),
                "provider": record.provider,
                "advisory_id": record.external_id,
                "source_status": source_statuses.get(
                    record.provider,
                    IntelligenceSource.Status.UNKNOWN,
                ),
            }
        )

    epss_records = [record for record in records if record.provider == AdvisoryRecord.Provider.EPSS]
    for record in epss_records:
        score = record.raw_record.get("epss")
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise CorrelationError("EPSS probability is invalid")
        score = float(score)
        if not math.isfinite(score) or not 0 <= score <= 1:
            raise CorrelationError("EPSS probability is outside the valid range")
        signals.append(
            {
                "name": "epss",
                "value": score,
                "points": round(score * 20, 2),
                "provider": record.provider,
                "advisory_id": record.external_id,
                "source_status": source_statuses.get(
                    record.provider,
                    IntelligenceSource.Status.UNKNOWN,
                ),
            }
        )

    kev_records = [
        record for record in records if record.provider == AdvisoryRecord.Provider.CISA_KEV
    ]
    if kev_records:
        record = kev_records[0]
        signals.append(
            {
                "name": "kev",
                "value": True,
                "points": 25,
                "provider": record.provider,
                "advisory_id": record.external_id,
                "source_status": source_statuses.get(
                    record.provider,
                    IntelligenceSource.Status.UNKNOWN,
                ),
            }
        )

    context: dict[str, Any] = {
        "exposure": finding.asset.exposure,
        "environment": finding.asset.environment,
        "points": 0,
    }
    if affected_status in {
        Finding.AffectedStatus.NOT_AFFECTED,
        Finding.AffectedStatus.NOT_APPLICABLE,
    }:
        return {
            "score": None,
            "level": RiskAssessment.Level.UNKNOWN,
            "policy_version": RISK_POLICY_VERSION,
            "factors": {
                "signals": signals,
                "context": context,
                "source_freshness": source_freshness,
            },
            "explanation": (
                "No priority score is assigned because the component is not affected "
                f"or the advisory does not apply to it. {freshness_note}"
            ),
        }
    if not signals:
        return {
            "score": None,
            "level": RiskAssessment.Level.UNKNOWN,
            "policy_version": RISK_POLICY_VERSION,
            "factors": {
                "signals": [],
                "context": context,
                "source_freshness": source_freshness,
            },
            "explanation": (
                f"No CVSS, EPSS, or KEV signal is available; priority is unknown. {freshness_note}"
            ),
        }

    context_points = 0
    if finding.asset.exposure == "internet_facing":
        context_points += 10
    if finding.asset.environment == "production":
        context_points += 5
    context["points"] = context_points
    score = min(100, round(sum(signal["points"] for signal in signals) + context_points))
    if score >= 80:
        level = RiskAssessment.Level.CRITICAL
    elif score >= 60:
        level = RiskAssessment.Level.HIGH
    elif score >= 35:
        level = RiskAssessment.Level.MEDIUM
    elif score >= 15:
        level = RiskAssessment.Level.LOW
    else:
        level = RiskAssessment.Level.INFORMATIONAL

    descriptions = [
        f"{signal['name'].upper()} {signal['value']} contributes {signal['points']} points"
        for signal in signals
    ]
    if context_points:
        descriptions.append(f"asset context contributes {context_points} points")
    if affected_status != Finding.AffectedStatus.CONFIRMED:
        descriptions.append("applicability is not confirmed, so priority is provisional")
    stale_sources = sorted(
        {
            signal["provider"]
            for signal in signals
            if signal["source_status"] != IntelligenceSource.Status.CURRENT
        }
    )
    if stale_sources:
        descriptions.append("signal source status is not current for " + ", ".join(stale_sources))
    descriptions.append(freshness_note.rstrip("."))
    return {
        "score": score,
        "level": level,
        "policy_version": RISK_POLICY_VERSION,
        "factors": {
            "signals": signals,
            "context": context,
            "source_freshness": source_freshness,
        },
        "explanation": "; ".join(descriptions) + ".",
    }


class FindingDecisionError(RuntimeError):
    """A human finding decision is invalid or unsafe."""


@transaction.atomic
def review_finding(
    *,
    finding_id: int,
    status: str,
    reason: str,
    actor: Any,
    assignee: Any | None = None,
) -> FindingDecision:
    """Record a human review without changing technical affected status or risk."""
    if status not in FindingDecision.Status.values:
        raise FindingDecisionError("Unsupported human review status")
    reason = reason.strip()
    if not reason:
        raise FindingDecisionError("A reason is required")
    if status == FindingDecision.Status.ASSIGNED and assignee is None:
        raise FindingDecisionError("An assignee is required")

    finding = Finding.objects.select_for_update().filter(pk=finding_id).first()
    if finding is None:
        raise FindingDecisionError("Finding not found")
    decision, _ = FindingDecision.objects.update_or_create(
        finding=finding,
        defaults={
            "status": status,
            "assignee": assignee,
            "decided_by": actor,
            "reason": reason,
        },
    )
    FindingDecisionEvent.objects.create(
        finding=finding,
        status=status,
        assignee=assignee,
        actor=actor,
        reason=reason,
    )
    return decision


@transaction.atomic
def reevaluate_findings(
    *, scan_run_id: int | None = None, vulnerability_ids: Iterable[int] | None = None
) -> int:
    """Reevaluate saved findings without invoking asset scanners."""
    findings: QuerySet[Finding] = Finding.objects.select_related(
        "asset",
        "component_occurrence__component",
        "vulnerability",
    ).prefetch_related(
        "vulnerability__advisory_records",
        "vulnerability__merged_members__advisory_records",
        "vulnerability__merged_into__advisory_records",
        "vulnerability__merged_into__merged_members__advisory_records",
    )
    if scan_run_id is not None:
        findings = findings.filter(scan_run_id=scan_run_id)
    if vulnerability_ids is not None:
        findings = findings.filter(vulnerability_id__in=vulnerability_ids)
    source_statuses = dict(IntelligenceSource.objects.values_list("provider", "status"))
    evaluated_at = timezone.now()
    evaluated = 0
    for finding in findings.iterator(chunk_size=200):
        vulnerability = _resolve_finding_vulnerability(finding)
        if vulnerability is not None and finding.vulnerability_id != vulnerability.pk:
            finding.vulnerability = vulnerability
        records: list[AdvisoryRecord] = []
        if finding.vulnerability is not None:
            root = finding.vulnerability.merged_into or finding.vulnerability
            group = [root, *root.merged_members.all()]
            records = [
                record
                for member in group
                for record in member.advisory_records.all()
                if record.is_active
            ]
        affected_status, confidence, correlation_evidence = _evaluate_applicability(
            finding,
            records,
            source_statuses,
        )
        evidence = finding.evidence
        if not isinstance(evidence, dict):
            raise CorrelationError("Finding evidence is not a JSON object")
        finding.evidence = {
            **evidence,
            "correlation": {
                "affected_status": affected_status,
                "confidence": confidence,
                "evaluated_at": evaluated_at.isoformat(),
                "evidence": correlation_evidence,
            },
        }
        finding.affected_status = affected_status
        finding.confidence = confidence
        finding.evaluated_at = evaluated_at
        finding.save(
            update_fields=[
                "vulnerability",
                "affected_status",
                "confidence",
                "evaluated_at",
                "evidence",
            ]
        )
        assessment = _risk_assessment(
            finding,
            records,
            affected_status,
            source_statuses,
        )
        RiskAssessment.objects.update_or_create(
            finding=finding,
            defaults=assessment,
        )
        evaluated += 1
    return evaluated


def recent_decision_events_prefetch() -> Prefetch[str, QuerySet[FindingDecisionEvent], str]:
    return Prefetch(
        "decision_events",
        queryset=FindingDecisionEvent.objects.order_by("-created_at", "-id")[:50],
        to_attr="recent_decision_events",
    )


def recent_decision_events(finding: Finding) -> list[FindingDecisionEvent]:
    events: list[FindingDecisionEvent] | None = getattr(finding, "recent_decision_events", None)
    if events is None:
        return list(finding.decision_events.order_by("-created_at", "-id")[:50])
    return events


def list_finding_summaries(
    *,
    asset_id: int | None,
    affected_status: str | None,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    """Return bounded, redacted finding and risk summaries."""
    if affected_status is not None and affected_status not in Finding.AffectedStatus.values:
        raise ValueError("Unsupported affected status")
    findings: QuerySet[Finding] = (
        Finding.objects.select_related(
            "asset",
            "asset__repository",
            "asset__container_image",
            "scan_run",
            "vulnerability",
            "risk_assessment",
            "decision",
            "decision__assignee",
            "decision__decided_by",
        )
        .prefetch_related(recent_decision_events_prefetch())
        .order_by("-created_at", "-id")
    )
    if asset_id is not None:
        findings = findings.filter(asset_id=asset_id)
    if affected_status is not None:
        findings = findings.filter(affected_status=affected_status)
    total = findings.count()
    items: list[dict[str, Any]] = []
    for finding in findings[offset : offset + limit]:
        finding_evidence = finding.evidence
        if not isinstance(finding_evidence, dict):
            raise CorrelationError("Finding evidence is not a JSON object")
        aliases = finding_evidence.get("aliases", [])
        if not isinstance(aliases, list) or any(not isinstance(item, str) for item in aliases):
            raise CorrelationError("Finding aliases are invalid")
        correlation = finding_evidence.get("correlation", {})
        if not isinstance(correlation, dict):
            raise CorrelationError("Finding correlation evidence is invalid")
        correlation_evidence = correlation.get("evidence", [])
        if not isinstance(correlation_evidence, list) or any(
            not isinstance(item, dict) for item in correlation_evidence
        ):
            raise CorrelationError("Finding correlation evidence is invalid")
        risk_assessment = getattr(finding, "risk_assessment", None)
        risk_summary = None
        if risk_assessment is not None:
            if not isinstance(risk_assessment.factors, dict):
                raise CorrelationError("Risk assessment factors are invalid")
            risk_summary = {
                "score": risk_assessment.score,
                "level": risk_assessment.level,
                "policy_version": risk_assessment.policy_version,
                "factors": risk_assessment.factors,
                "explanation": risk_assessment.explanation,
                "assessed_at": risk_assessment.assessed_at,
            }
        decision = getattr(finding, "decision", None)
        decision_summary = None
        if decision is not None:
            decision_summary = {
                "status": decision.status,
                "assignee_id": decision.assignee_id,
                "decided_by_id": decision.decided_by_id,
                "reason": decision.reason,
                "updated_at": decision.updated_at,
            }
        decision_events = [
            {
                "status": event.status,
                "assignee_id": event.assignee_id,
                "actor_id": event.actor_id,
                "reason": event.reason,
                "created_at": event.created_at,
            }
            for event in recent_decision_events(finding)
        ]
        items.append(
            {
                "id": finding.pk,
                "asset_id": finding.asset_id,
                "asset_name": finding.asset.name,
                "scan_run_id": finding.scan_run_id,
                "asset_source_status": scan_source_status_for_asset(
                    asset=finding.asset, metadata=finding.scan_run.metadata
                ),
                "vulnerability_id": finding.vulnerability_id,
                "canonical_id": (
                    finding.vulnerability.canonical_id
                    if finding.vulnerability is not None
                    else None
                ),
                "source": finding.source,
                "kind": finding.kind,
                "external_id": finding.external_id,
                "aliases": aliases,
                "package_name": finding.package_name,
                "package_version": finding.package_version,
                "severity": finding.severity,
                "title": finding.title,
                "source_path": finding.source_path,
                "line_number": finding.line_number,
                "affected_status": finding.affected_status,
                "confidence": finding.confidence,
                "evaluated_at": finding.evaluated_at,
                "correlation_evidence": correlation_evidence,
                "risk_assessment": risk_summary,
                "decision": decision_summary,
                "decision_events": decision_events,
            }
        )
    return {"total": total, "limit": limit, "offset": offset, "items": items}
