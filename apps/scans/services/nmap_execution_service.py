from __future__ import annotations

import os
import shlex
import socket
import subprocess
import tempfile
from pathlib import Path

from django.conf import settings
from django.db import transaction

from apps.scans.models import ScanExecution, ScanPortResult, ScanResult
from apps.scans.services.execution_service import (
    assign_execution,
    complete_execution,
    fail_execution,
    log_execution_event,
    start_execution,
    update_execution_progress,
)
from apps.scans.services.nmap_command_service import build_nmap_command
from apps.scans.services.nmap_parser import ParsedNmapResult, parse_nmap_outputs


HIGH_RISK_PORTS = {21, 23, 25, 135, 137, 138, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 11211}
MEDIUM_RISK_PORTS = {53, 69, 111, 161, 389, 636, 8080, 8443, 27017}
HIGH_RISK_SERVICES = {"telnet", "ftp", "microsoft-ds", "ms-wbt-server", "redis", "vnc", "mysql"}
MEDIUM_RISK_SERVICES = {"http", "https", "http-proxy", "https-alt", "domain", "ldap", "snmp", "postgresql"}


def _risk_level_for_port(*, port: int, state: str, service_name: str) -> str:
    normalized_state = (state or "").strip().lower()
    if normalized_state != "open":
        return ScanPortResult.RiskLevel.INFO

    normalized_service = (service_name or "").strip().lower()
    if port in HIGH_RISK_PORTS or normalized_service in HIGH_RISK_SERVICES:
        return ScanPortResult.RiskLevel.HIGH
    if port in MEDIUM_RISK_PORTS or normalized_service in MEDIUM_RISK_SERVICES:
        return ScanPortResult.RiskLevel.MEDIUM
    return ScanPortResult.RiskLevel.LOW


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _persist_result_for_execution(
    execution: ScanExecution,
    *,
    parsed: ParsedNmapResult,
    raw_output_text: str,
    raw_error_output: str,
    raw_output_xml: str,
    executed_command: str,
) -> ScanResult:
    summary = parsed.parsed_output.get("summary", {}) if isinstance(parsed.parsed_output, dict) else {}
    state_breakdown = summary.get("state_breakdown", {}) if isinstance(summary, dict) else {}
    open_ports = _safe_int(summary.get("open_ports"), _safe_int(state_breakdown.get("open")))
    closed_ports = _safe_int(summary.get("closed_ports"), _safe_int(state_breakdown.get("closed")))
    filtered_ports = _safe_int(summary.get("filtered_ports"), _safe_int(state_breakdown.get("filtered")))

    host_status = parsed.host_status if parsed.host_status in dict(ScanResult.HostStatus.choices) else ScanResult.HostStatus.UNKNOWN
    unique_services = {
        (row.service_name or "").strip().lower()
        for row in parsed.ports
        if (row.service_name or "").strip()
    }
    result_summary = {
        "service_count": len(unique_services),
        "protocol_count": len({(row.protocol or "").strip().lower() for row in parsed.ports if row.protocol}),
        "state_breakdown": state_breakdown,
        "validation": parsed.validation,
        "warnings_count": len(parsed.warnings),
    }

    with transaction.atomic():
        result, _created = ScanResult.objects.update_or_create(
            execution=execution,
            defaults={
                "target_snapshot": execution.scan_request.target.target_value,
                "host_status": host_status,
                "total_open_ports": max(open_ports, 0),
                "total_closed_ports": max(closed_ports, 0),
                "total_filtered_ports": max(filtered_ports, 0),
                "total_services_detected": len(unique_services),
                "os_guess": parsed.os_guess or "",
                "executed_command": executed_command,
                "raw_output_text": raw_output_text,
                "raw_error_output": raw_error_output,
                "raw_output_xml": raw_output_xml,
                "parsed_output_json": parsed.parsed_output if isinstance(parsed.parsed_output, dict) else {},
                "traceroute_data_json": parsed.traceroute_rows,
                "script_output_json": parsed.script_output,
                "parser_warnings_json": parsed.warnings,
                "parser_validation_json": parsed.validation,
                "result_summary": result_summary,
            },
        )

        result.port_results.all().delete()
        bulk_rows = []
        for row in parsed.ports:
            bulk_rows.append(
                ScanPortResult(
                    result=result,
                    port=row.port,
                    protocol=(row.protocol or "tcp").strip().lower(),
                    state=(row.state or "unknown").strip().lower(),
                    service_name=(row.service_name or "").strip(),
                    service_version=(row.service_version or "").strip(),
                    risk_level=_risk_level_for_port(
                        port=row.port,
                        state=row.state,
                        service_name=row.service_name,
                    ),
                    extra_data_json=row.extra_data if isinstance(row.extra_data, dict) else {},
                )
            )
        if bulk_rows:
            ScanPortResult.objects.bulk_create(bulk_rows)
    return result


def _worker_name(default_worker_name: str | None = None) -> str:
    if default_worker_name:
        return default_worker_name
    env_value = (os.environ.get("SCANOPS_SCAN_WORKER_NAME") or "").strip()
    if env_value:
        return env_value
    return f"scanops-{socket.gethostname()}"


def run_execution_with_nmap(
    execution: ScanExecution,
    *,
    worker_name: str | None = None,
    nmap_binary: str | None = None,
    timeout_seconds: int | None = None,
) -> ScanResult:
    if execution.status in {ScanExecution.Status.COMPLETED, ScanExecution.Status.CANCELLED} and hasattr(execution, "result"):
        return execution.result

    worker = _worker_name(worker_name)
    if not execution.worker_name:
        assign_execution(execution, worker)

    start_execution(execution, worker_name=worker)
    update_execution_progress(
        execution,
        progress_percent=8,
        stage="Preparing Command",
        message="Building Nmap command for execution.",
    )

    nmap_binary = (nmap_binary or getattr(settings, "SCANOPS_NMAP_BINARY", "nmap")).strip() or "nmap"
    timeout_seconds = timeout_seconds or int(getattr(settings, "SCANOPS_SCAN_TIMEOUT_SECONDS", 900))

    xml_fd, xml_path = tempfile.mkstemp(prefix=f"scanops_{execution.pk}_", suffix=".xml")
    os.close(xml_fd)
    raw_output_text = ""
    raw_error_output = ""
    raw_output_xml = ""
    command_display = ""
    return_code = 1

    try:
        command = build_nmap_command(
            execution.scan_request,
            xml_output_path=xml_path,
            nmap_binary=nmap_binary,
        )
        command_display = shlex.join(command)
        log_execution_event(
            execution,
            "command",
            f"Executing command: {command_display}",
            metadata={"command": command, "timeout_seconds": timeout_seconds},
        )
        update_execution_progress(
            execution,
            progress_percent=18,
            stage="Running Nmap",
            message="Nmap scan is running.",
        )

        completed = subprocess.run(  # noqa: S603
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
        raw_output_text = _coerce_text(completed.stdout)
        raw_error_output = _coerce_text(completed.stderr)
        return_code = completed.returncode
    except subprocess.TimeoutExpired as exc:
        raw_output_text = _coerce_text(exc.stdout)
        raw_error_output = f"{_coerce_text(exc.stderr)}\nTimeout after {timeout_seconds} seconds.".strip()
        return_code = 124
        log_execution_event(
            execution,
            "timeout",
            f"Nmap command timed out after {timeout_seconds} seconds.",
        )
    except FileNotFoundError:
        raw_error_output = f"Nmap binary not found: {nmap_binary}"
        return_code = 127
        log_execution_event(
            execution,
            "failed",
            raw_error_output,
        )
    except Exception as exc:  # noqa: BLE001
        raw_error_output = f"Unexpected execution error: {exc}"
        return_code = 1
        log_execution_event(
            execution,
            "failed",
            raw_error_output,
        )
    finally:
        xml_file = Path(xml_path)
        if xml_file.exists():
            try:
                raw_output_xml = xml_file.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                raw_error_output = f"{raw_error_output}\nFailed to read XML output: {exc}".strip()
            try:
                xml_file.unlink()
            except OSError:
                pass

    update_execution_progress(
        execution,
        progress_percent=76,
        stage="Parsing Output",
        message="Parsing and validating Nmap output.",
    )
    parsed = parse_nmap_outputs(
        raw_output_text=raw_output_text,
        raw_output_xml=raw_output_xml,
        target_snapshot=execution.scan_request.target.target_value,
    )
    result = _persist_result_for_execution(
        execution,
        parsed=parsed,
        raw_output_text=raw_output_text,
        raw_error_output=raw_error_output,
        raw_output_xml=raw_output_xml,
        executed_command=command_display,
    )

    for warning in parsed.warnings:
        log_execution_event(
            execution,
            "parser_warning",
            warning,
        )

    if return_code == 0:
        complete_execution(
            execution,
            message=f"Scan completed with {len(parsed.ports)} parsed port rows.",
        )
        return result

    fail_execution(
        execution,
        message=f"Scan failed with exit code {return_code}. Stored partial output for review.",
    )
    log_execution_event(
        execution,
        "stderr",
        raw_error_output[:4000] if raw_error_output else "No stderr output captured.",
        metadata={"return_code": return_code},
    )
    return result
