"""Mark a scan as interrupted only after an operator confirms offline maintenance."""

from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import transaction
from django.utils import timezone

from ciclosec.scans.models import ScanRun


class Command(BaseCommand):
    help = (
        "Mark an interrupted scan as failed after stopping all workers and scanner processes. "
        "This command cannot verify that they have stopped."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("scan_id", type=int)
        parser.add_argument("--operator", required=True)
        parser.add_argument(
            "--confirm-all-workers-and-scanners-stopped",
            action="store_true",
            help="Confirm all workers and their scanner processes are stopped on every host.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        if not options["confirm_all_workers_and_scanners_stopped"]:
            raise CommandError("Confirm that all workers and scanner processes are stopped.")
        operator = options["operator"].strip()
        if not operator or len(operator) > 128 or not operator.isprintable():
            raise CommandError("Operator must contain 1 to 128 printable characters.")
        scan_id = options["scan_id"]
        if scan_id <= 0:
            raise CommandError("Scan ID must be positive.")

        with transaction.atomic():
            try:
                scan = ScanRun.objects.select_for_update().get(pk=scan_id)
            except ScanRun.DoesNotExist as error:
                raise CommandError("Scan not found.") from error
            now = timezone.now()
            if (
                scan.status != ScanRun.Status.RUNNING
                or scan.started_at is None
                or scan.finished_at is not None
                or scan.started_at > now
            ):
                raise CommandError("Scan is not a consistent, started, unfinished running scan.")
            if not isinstance(scan.metadata, dict) or "manual_recovery" in scan.metadata:
                raise CommandError("Scan metadata is invalid or already contains a recovery.")
            codes = scan.metadata.get("diagnostic_codes", [])
            if not isinstance(codes, list) or any(not isinstance(code, str) for code in codes):
                raise CommandError("Scan diagnostic metadata is invalid.")
            if ScanRun.Diagnostic.MANUALLY_RECOVERED not in codes:
                codes = [*codes, ScanRun.Diagnostic.MANUALLY_RECOVERED]
            scan.metadata = {
                **scan.metadata,
                "diagnostic_codes": codes,
                "manual_recovery": {
                    "operator": operator,
                    "confirmed_all_workers_and_scanners_stopped": True,
                },
            }
            scan.status = ScanRun.Status.FAILED
            scan.finished_at = now
            if not scan.error_summary:
                scan.error_summary = "Operator marked the scan as interrupted during maintenance."
            scan.save(update_fields=["status", "finished_at", "error_summary", "metadata"])

        self.stdout.write(f"Scan {scan_id} marked as failed; no new scan was started.")
