from __future__ import annotations

from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.scans.models import ScanExecution
from apps.scans.services.execution_service import log_execution_event
from apps.scans.services.nmap_execution_service import run_execution_with_nmap


class Command(BaseCommand):
    help = "Process queued scan executions using real Nmap execution and parser pipeline."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=1, help="Maximum number of executions to process.")
        parser.add_argument(
            "--execution-id",
            type=str,
            default="",
            help="Process a specific execution_id instead of pulling from queue.",
        )
        parser.add_argument("--worker-name", type=str, default="", help="Override worker name for this run.")
        parser.add_argument("--nmap-binary", type=str, default="", help="Override Nmap binary path.")
        parser.add_argument(
            "--timeout-seconds",
            type=int,
            default=0,
            help="Override scan timeout for this run.",
        )
        parser.add_argument(
            "--include-running",
            action="store_true",
            help="Also process executions currently marked running.",
        )
        parser.add_argument(
            "--resume-stale-after-seconds",
            type=int,
            default=900,
            help="When --include-running is set, re-queue running executions older than this threshold.",
        )

    @staticmethod
    def _requeue_stale_running(*, stale_after_seconds: int) -> int:
        cutoff = timezone.now() - timedelta(seconds=max(60, stale_after_seconds))
        stale_qs = ScanExecution.objects.filter(
            status=ScanExecution.Status.RUNNING,
            queue_status=ScanExecution.QueueStatus.PROCESSING,
            is_archived=False,
            updated_at__lt=cutoff,
        ).order_by("updated_at")

        updated = 0
        for execution in stale_qs:
            execution.status = ScanExecution.Status.QUEUED
            execution.queue_status = ScanExecution.QueueStatus.WAITING
            execution.current_stage = "Queued"
            execution.status_message = "Re-queued automatically after worker timeout."
            execution.save(update_fields=["status", "queue_status", "current_stage", "status_message", "updated_at"])
            log_execution_event(
                execution,
                "requeued",
                "Execution re-queued after stale running timeout.",
                metadata={"stale_after_seconds": stale_after_seconds},
            )
            updated += 1
        return updated

    def handle(self, *args, **options):
        limit = max(1, int(options["limit"]))
        execution_id = (options.get("execution_id") or "").strip()
        worker_name = (options.get("worker_name") or "").strip() or None
        nmap_binary = (options.get("nmap_binary") or "").strip() or None
        timeout_seconds = int(options.get("timeout_seconds") or 0) or None
        include_running = bool(options.get("include_running"))
        resume_stale_after_seconds = int(options.get("resume_stale_after_seconds") or 900)

        if include_running:
            requeued = self._requeue_stale_running(stale_after_seconds=resume_stale_after_seconds)
            if requeued:
                self.stdout.write(self.style.WARNING(f"Re-queued {requeued} stale running execution(s)."))

        queryset = ScanExecution.objects.select_related("scan_request__target", "scan_request__profile").order_by("priority", "created_at")
        if execution_id:
            queryset = queryset.filter(execution_id=execution_id)
        else:
            allowed_statuses = [ScanExecution.Status.QUEUED]
            if include_running:
                allowed_statuses.append(ScanExecution.Status.RUNNING)
            queryset = queryset.filter(status__in=allowed_statuses, is_archived=False)[:limit]

        executions = list(queryset)
        if not executions:
            self.stdout.write(self.style.WARNING("No matching executions found for processing."))
            return

        processed = 0
        failed = 0
        for execution in executions:
            self.stdout.write(f"Processing {execution.execution_id} ({execution.status})")
            try:
                result = run_execution_with_nmap(
                    execution,
                    worker_name=worker_name,
                    nmap_binary=nmap_binary,
                    timeout_seconds=timeout_seconds,
                )
                execution.refresh_from_db(fields=["status", "queue_status"])
                processed += 1
                if execution.status == ScanExecution.Status.FAILED:
                    failed += 1
                    self.stdout.write(
                        self.style.WARNING(
                            f"{execution.execution_id} finished with FAILED status; result #{result.pk} persisted for review."
                        )
                    )
                else:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"{execution.execution_id} completed; result #{result.pk} stored with {result.port_results.count()} port rows."
                        )
                    )
            except Exception as exc:  # noqa: BLE001
                failed += 1
                self.stderr.write(self.style.ERROR(f"{execution.execution_id} crashed: {exc}"))

        self.stdout.write(
            self.style.SUCCESS(
                f"Queue processing finished. Processed: {processed}, Failed: {failed}, Total selected: {len(executions)}."
            )
        )
