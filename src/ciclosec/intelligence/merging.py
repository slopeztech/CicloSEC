"""Reversible grouping of vulnerability identities without moving their references."""

from __future__ import annotations

from collections.abc import Generator, Iterable
from itertools import zip_longest

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from ciclosec.findings.models import Finding
from ciclosec.intelligence.models import (
    AdvisoryRecord,
    SyncRun,
    Vulnerability,
    VulnerabilityAlias,
    VulnerabilityMerge,
    VulnerabilityMergeMember,
    VulnerabilityMergeReference,
)


class MergeConflict(RuntimeError):
    """An equivalence cannot be applied or reversed safely."""


def _closable_rows(rows: Iterable[tuple[int, int]]) -> Generator[tuple[int, int], None, None]:
    yield from rows


def root_id(vulnerability: Vulnerability) -> int:
    return vulnerability.merged_into_id or vulnerability.pk


def group_ids(vulnerability: Vulnerability) -> list[int]:
    root = root_id(vulnerability)
    return list(
        Vulnerability.objects.filter(Q(pk=root) | Q(merged_into_id=root)).values_list(
            "pk", flat=True
        )
    )


def lock_alias_roots(aliases: Iterable[VulnerabilityAlias]) -> None:
    """Prevent group changes while resolving aliases inside a transaction."""
    aliases = list(aliases)
    roots = {root_id(alias.vulnerability) for alias in aliases}
    locked = list(Vulnerability.objects.select_for_update().filter(pk__in=roots).order_by("pk"))
    if len(locked) != len(roots) or any(root.merged_into_id is not None for root in locked):
        raise MergeConflict("Vulnerability groups changed during resolution; retry")
    current = Vulnerability.objects.filter(
        pk__in=[alias.vulnerability_id for alias in aliases]
    ).values_list("pk", "merged_into_id")
    if {merged_into or pk for pk, merged_into in current} != roots:
        raise MergeConflict("Vulnerability groups changed during resolution; retry")


@transaction.atomic
def merge_osv_equivalents(
    vulnerabilities: Iterable[Vulnerability],
    *,
    identifiers: list[str],
    evidence_id: str,
    run: SyncRun,
) -> Vulnerability:
    """Group OSV aliases, keeping every vulnerability and its references in place."""
    roots = sorted({root_id(vulnerability) for vulnerability in vulnerabilities})
    if not roots:
        raise MergeConflict("OSV equivalence has no existing vulnerability")
    locked_roots = list(
        Vulnerability.objects.select_for_update().filter(pk__in=roots).order_by("pk")
    )
    if len(locked_roots) != len(roots) or any(root.merged_into_id for root in locked_roots):
        raise MergeConflict("Vulnerability groups changed during reconciliation; retry")
    if len(roots) == 1:
        return locked_roots[0]

    members = list(
        Vulnerability.objects.select_for_update()
        .filter(Q(pk__in=roots) | Q(merged_into_id__in=roots))
        .order_by("pk")
    )
    member_ids = Vulnerability.objects.filter(
        Q(pk__in=roots) | Q(merged_into_id__in=roots)
    ).values_list("pk", flat=True)
    cves = set(
        VulnerabilityAlias.objects.filter(
            vulnerability_id__in=member_ids, namespace=VulnerabilityAlias.Namespace.CVE
        ).values_list("identifier", flat=True)
    )
    cves.update(identifier for identifier in identifiers if identifier.startswith("CVE-"))
    if len(cves) > 1:
        raise MergeConflict("OSV equivalence contains multiple CVE identifiers; review required")

    for rejected in VulnerabilityMerge.objects.filter(
        reverted_at__isnull=False, members__vulnerability_id__in=member_ids
    ).distinct():
        old_roots = set(
            rejected.members.filter(vulnerability_id__in=member_ids).values_list(
                "previous_root_id", flat=True
            )
        )
        if len(old_roots) > 1:
            raise MergeConflict("OSV equivalence was previously reversed; review required")

    canonical = locked_roots[0]
    merge = VulnerabilityMerge.objects.create(
        canonical=canonical,
        provider="osv",
        evidence_id=evidence_id,
        identifiers=list(dict.fromkeys(identifiers)),
        sync_run=run,
    )
    VulnerabilityMergeMember.objects.bulk_create(
        [
            VulnerabilityMergeMember(
                merge=merge,
                vulnerability=member,
                previous_root_id=root_id(member),
            )
            for member in members
        ],
        batch_size=1000,
    )
    Vulnerability.objects.filter(Q(pk__in=roots) | Q(merged_into_id__in=roots)).exclude(
        pk=canonical.pk
    ).update(merged_into=canonical)
    return canonical


def record_merge_references(merge: VulnerabilityMerge) -> None:
    """Capture original reference owners after the triggering OSV record is saved."""
    ids = merge.members.values_list("vulnerability_id", flat=True)
    for kind, model in (
        ("alias", VulnerabilityAlias),
        ("advisory", AdvisoryRecord),
        ("finding", Finding),
    ):
        references: list[VulnerabilityMergeReference] = []
        rows = (
            model.objects.select_for_update()
            .filter(vulnerability_id__in=ids)
            .order_by("pk")
            .values_list("pk", "vulnerability_id")
        )
        for object_id, vulnerability_id in rows.iterator(chunk_size=1000):
            references.append(
                VulnerabilityMergeReference(
                    merge=merge,
                    kind=kind,
                    object_id=object_id,
                    vulnerability_id=vulnerability_id,
                )
            )
            if len(references) == 1000:
                VulnerabilityMergeReference.objects.bulk_create(references)
                references.clear()
        if references:
            VulnerabilityMergeReference.objects.bulk_create(references)
    merge.references_recorded_at = timezone.now()
    merge.save(update_fields=["references_recorded_at"])


@transaction.atomic
def reverse_merge(merge_id: int, *, operator: str, reason: str) -> None:
    """Reverse a decision only when no subsequent active decision depends on it."""
    if not operator.strip() or not reason.strip():
        raise MergeConflict("An operator and reason are required to reverse a merge")
    merge = VulnerabilityMerge.objects.select_for_update().get(pk=merge_id)
    if merge.reverted_at is not None:
        raise MergeConflict("The merge has already been reversed")
    if merge.references_recorded_at is None:
        raise MergeConflict("The merge does not have a complete reference snapshot")
    entries = list(merge.members.select_related("vulnerability").order_by("vulnerability_id"))
    ids = merge.members.values_list("vulnerability_id", flat=True)
    members = list(Vulnerability.objects.select_for_update().filter(pk__in=ids).order_by("pk"))
    if len(members) != len(entries) or any(
        root_id(member) != merge.canonical_id for member in members
    ):
        raise MergeConflict("Vulnerability groups changed after this merge")
    if VulnerabilityMergeMember.objects.filter(
        vulnerability_id__in=ids,
        merge__reverted_at__isnull=True,
        merge__pk__gt=merge.pk,
    ).exists():
        raise MergeConflict("A later active merge must be reversed first")
    for kind, model in (
        ("alias", VulnerabilityAlias),
        ("advisory", AdvisoryRecord),
        ("finding", Finding),
    ):
        current = _closable_rows(
            model.objects.select_for_update()
            .filter(vulnerability_id__in=ids)
            .order_by("pk")
            .values_list("pk", "vulnerability_id")
            .iterator(chunk_size=1000)
        )
        recorded = _closable_rows(
            merge.references.filter(kind=kind)
            .order_by("object_id")
            .values_list("object_id", "vulnerability_id")
            .iterator(chunk_size=1000)
        )
        try:
            changed = any(before != after for before, after in zip_longest(recorded, current))
        finally:
            current.close()
            recorded.close()
        if changed:
            raise MergeConflict(f"{kind} references changed after the merge; review required")
    previous_groups: dict[int | None, list[int]] = {}
    for entry in entries:
        previous = (
            None if entry.vulnerability_id == entry.previous_root_id else entry.previous_root_id
        )
        previous_groups.setdefault(previous, []).append(entry.vulnerability_id)
    for previous, member_ids in previous_groups.items():
        for start in range(0, len(member_ids), 1000):
            Vulnerability.objects.filter(pk__in=member_ids[start : start + 1000]).update(
                merged_into_id=previous
            )
    merge.reverted_at = timezone.now()
    merge.reverted_by = operator.strip()
    merge.revert_reason = reason.strip()
    merge.save(update_fields=["reverted_at", "reverted_by", "revert_reason"])
    from ciclosec.findings.services import reevaluate_findings

    reevaluate_findings(vulnerability_ids=ids)
