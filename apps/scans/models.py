from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from apps.targets.models import Target


def generate_execution_id() -> str:
    return f"EXE-{timezone.now():%Y%m%d}-{uuid.uuid4().hex[:8].upper()}"


class ScanProfile(models.Model):
    class ScanType(models.TextChoices):
        HOST_DISCOVERY = "host_discovery", "Host Discovery"
        QUICK_TCP = "quick_tcp", "Quick TCP"
        TOP_100 = "top_100", "Top 100"
        TOP_1000 = "top_1000", "Top 1000"
        SERVICE_DETECTION = "service_detection", "Service Detection"
        SAFE_BASIC = "safe_basic", "Safe Basic"

    class TimingProfile(models.TextChoices):
        NORMAL = "normal", "Normal"
        BALANCED = "balanced", "Balanced"
        FAST = "fast", "Fast"

    name = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    scan_type = models.CharField(max_length=32, choices=ScanType.choices, default=ScanType.SAFE_BASIC)
    port_scope = models.CharField(max_length=128, blank=True, default="")
    enable_host_discovery = models.BooleanField(default=True)
    enable_service_detection = models.BooleanField(default=True)
    enable_version_detection = models.BooleanField(default=False)
    enable_os_detection = models.BooleanField(default=False)
    enable_traceroute = models.BooleanField(default=False)
    enable_dns_resolution = models.BooleanField(default=True)
    timing_profile = models.CharField(max_length=16, choices=TimingProfile.choices, default=TimingProfile.NORMAL)
    is_system = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="created_scan_profiles",
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("is_system", "name")

    def __str__(self) -> str:
        return self.name


class ScanRequest(models.Model):
    class Status(models.TextChoices):
        DRAFT = "draft", "Draft"
        PENDING = "pending", "Pending"
        VALIDATED = "validated", "Validated"
        REJECTED = "rejected", "Rejected"

    target = models.ForeignKey(Target, related_name="scan_requests", on_delete=models.PROTECT)
    profile = models.ForeignKey(
        ScanProfile,
        related_name="scan_requests",
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
    )
    scan_type = models.CharField(max_length=32, choices=ScanProfile.ScanType.choices, default=ScanProfile.ScanType.SAFE_BASIC)
    port_input = models.CharField(max_length=255, blank=True, default="")
    enable_host_discovery = models.BooleanField(default=True)
    enable_service_detection = models.BooleanField(default=True)
    enable_version_detection = models.BooleanField(default=False)
    enable_os_detection = models.BooleanField(default=False)
    enable_traceroute = models.BooleanField(default=False)
    enable_dns_resolution = models.BooleanField(default=True)
    timing_profile = models.CharField(max_length=16, choices=ScanProfile.TimingProfile.choices, default=ScanProfile.TimingProfile.NORMAL)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    validation_summary = models.TextField(blank=True, default="")
    notes = models.TextField(blank=True)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="requested_scans",
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
    )
    requested_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-requested_at",)
        indexes = [
            models.Index(fields=["status", "requested_at"]),
            models.Index(fields=["scan_type"]),
        ]

    def __str__(self) -> str:
        return f"{self.target} - {self.get_scan_type_display()} ({self.status})"


class ScanExecution(models.Model):
    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"
        CANCELLED = "cancelled", "Cancelled"

    class QueueStatus(models.TextChoices):
        WAITING = "waiting", "Waiting"
        ASSIGNED = "assigned", "Assigned"
        PROCESSING = "processing", "Processing"
        DONE = "done", "Done"
        ERROR = "error", "Error"

    scan_request = models.ForeignKey(
        ScanRequest,
        related_name="executions",
        on_delete=models.CASCADE,
    )
    execution_id = models.CharField(max_length=64, unique=True, default=generate_execution_id, editable=False)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.QUEUED)
    queue_status = models.CharField(max_length=16, choices=QueueStatus.choices, default=QueueStatus.WAITING)
    started_at = models.DateTimeField(blank=True, null=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)
    duration_seconds = models.PositiveIntegerField(default=0)
    worker_name = models.CharField(max_length=120, blank=True)
    progress_percent = models.PositiveSmallIntegerField(default=0)
    current_stage = models.CharField(max_length=120, blank=True)
    status_message = models.TextField(blank=True)
    is_archived = models.BooleanField(default=False)
    priority = models.PositiveSmallIntegerField(default=3)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["status", "queue_status", "created_at"]),
            models.Index(fields=["is_archived", "created_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.execution_id} ({self.status})"


class ScanResult(models.Model):
    class HostStatus(models.TextChoices):
        UP = "up", "Up"
        DOWN = "down", "Down"
        PARTIAL = "partial", "Partial"
        UNKNOWN = "unknown", "Unknown"

    execution = models.OneToOneField(
        ScanExecution,
        related_name="result",
        on_delete=models.CASCADE,
    )
    target_snapshot = models.CharField(max_length=255)
    host_status = models.CharField(max_length=16, choices=HostStatus.choices, default=HostStatus.UNKNOWN)
    total_open_ports = models.PositiveIntegerField(default=0)
    total_closed_ports = models.PositiveIntegerField(default=0)
    total_filtered_ports = models.PositiveIntegerField(default=0)
    total_services_detected = models.PositiveIntegerField(default=0)
    os_guess = models.CharField(max_length=255, blank=True)
    executed_command = models.TextField(blank=True, default="")
    raw_output_text = models.TextField(blank=True)
    raw_error_output = models.TextField(blank=True, default="")
    raw_output_xml = models.TextField(blank=True)
    parsed_output_json = models.JSONField(default=dict, blank=True)
    traceroute_data_json = models.JSONField(default=list, blank=True)
    script_output_json = models.JSONField(default=dict, blank=True)
    parser_warnings_json = models.JSONField(default=list, blank=True)
    parser_validation_json = models.JSONField(default=dict, blank=True)
    result_summary = models.JSONField(default=dict, blank=True)
    generated_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-generated_at",)
        indexes = [
            models.Index(fields=["host_status", "generated_at"]),
            models.Index(fields=["target_snapshot"]),
        ]

    def __str__(self) -> str:
        return f"Result {self.pk} - {self.target_snapshot}"


class ScanPortResult(models.Model):
    class RiskLevel(models.TextChoices):
        INFO = "info", "Info"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"

    result = models.ForeignKey(
        ScanResult,
        related_name="port_results",
        on_delete=models.CASCADE,
    )
    port = models.PositiveIntegerField()
    protocol = models.CharField(max_length=16, default="tcp")
    state = models.CharField(max_length=32, default="open")
    service_name = models.CharField(max_length=120, blank=True)
    service_version = models.CharField(max_length=255, blank=True)
    risk_level = models.CharField(max_length=16, choices=RiskLevel.choices, default=RiskLevel.INFO)
    extra_data_json = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ("port", "protocol")
        constraints = [
            models.UniqueConstraint(
                fields=["result", "port", "protocol"],
                name="uniq_scan_port_result_per_protocol",
            )
        ]
        indexes = [
            models.Index(fields=["risk_level", "port"]),
        ]

    def __str__(self) -> str:
        return f"{self.result_id}:{self.port}/{self.protocol} ({self.state})"


class ScanEventLog(models.Model):
    execution = models.ForeignKey(
        ScanExecution,
        related_name="event_logs",
        on_delete=models.CASCADE,
    )
    event_type = models.CharField(max_length=64)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    metadata_json = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["event_type", "created_at"]),
            models.Index(fields=["execution", "created_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.execution.execution_id} - {self.event_type}"
