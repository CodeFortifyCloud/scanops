from __future__ import annotations

import random

from django.db import transaction
from django.utils import timezone

from apps.ops.services import data_visibility_service
from apps.scans.models import ScanExecution, ScanPortResult, ScanResult
from apps.targets.models import Target


COMMON_PORT_CATALOG = [
    (22, "tcp", "ssh", "OpenSSH 8.2p1", ScanPortResult.RiskLevel.LOW),
    (53, "udp", "domain", "BIND 9.16", ScanPortResult.RiskLevel.INFO),
    (80, "tcp", "http", "nginx 1.18.0", ScanPortResult.RiskLevel.LOW),
    (123, "udp", "ntp", "NTP daemon", ScanPortResult.RiskLevel.INFO),
    (443, "tcp", "https", "nginx 1.20.1", ScanPortResult.RiskLevel.LOW),
    (445, "tcp", "microsoft-ds", "SMBv2", ScanPortResult.RiskLevel.MEDIUM),
    (3306, "tcp", "mysql", "MySQL 8.0.28", ScanPortResult.RiskLevel.HIGH),
    (3389, "tcp", "ms-wbt-server", "RDP Service", ScanPortResult.RiskLevel.HIGH),
    (5432, "tcp", "postgresql", "PostgreSQL 14", ScanPortResult.RiskLevel.MEDIUM),
    (8080, "tcp", "http-proxy", "Squid 4.10", ScanPortResult.RiskLevel.MEDIUM),
    (8443, "tcp", "https-alt", "Jetty 9", ScanPortResult.RiskLevel.MEDIUM),
    (9000, "tcp", "cslistener", "Internal Agent", ScanPortResult.RiskLevel.INFO),
]

OS_CATALOG = [
    "Linux 5.4",
    "Linux 6.x",
    "Ubuntu 22.04",
    "Windows Server 2019",
    "FreeBSD 13",
]


def _build_raw_output(target: str, open_ports: list[tuple]) -> str:
    lines = [
        f"# Nmap simulated run for {target}",
        f"Starting Nmap at {timezone.now():%Y-%m-%d %H:%M:%S %Z}",
        f"Host {target} is up.",
        "PORT     STATE SERVICE      VERSION",
    ]
    for port, protocol, service, version, _risk in sorted(open_ports, key=lambda x: x[0]):
        lines.append(f"{port}/{protocol:<4} open  {service:<12} {version}")
    lines.append("Nmap done: 1 IP address (1 host up) scanned.")
    return "\n".join(lines)


def _build_traceroute(seed: int) -> list[dict]:
    rng = random.Random(seed)
    hops = []
    for index in range(1, 5):
        hops.append(
            {
                "hop": index,
                "host": f"10.0.{rng.randint(1, 10)}.{rng.randint(1, 254)}",
                "latency_ms": round(rng.uniform(0.5, 15.5), 2),
            }
        )
    return hops


@transaction.atomic
def generate_mock_result_for_execution(execution: ScanExecution, force: bool = False) -> ScanResult:
    if execution.status != ScanExecution.Status.COMPLETED and not force:
        raise ValueError("Result generation requires a completed execution unless force=True.")

    target_value = execution.scan_request.target.target_value
    seed = sum(ord(ch) for ch in execution.execution_id)
    rng = random.Random(seed)
    open_port_count = rng.randint(4, 8)
    open_ports = rng.sample(COMMON_PORT_CATALOG, k=open_port_count)
    closed_ports = max(0, 1000 - open_port_count - rng.randint(5, 30))
    filtered_ports = max(0, 1000 - open_port_count - closed_ports)
    os_guess = rng.choice(OS_CATALOG)

    parsed_ports = []
    for port, protocol, service, version, risk in open_ports:
        parsed_ports.append(
            {
                "port": port,
                "protocol": protocol,
                "state": "open",
                "service": service,
                "version": version,
                "risk": risk,
            }
        )

    raw_output_text = _build_raw_output(target_value, open_ports)
    traceroute = _build_traceroute(seed)
    script_output = {
        "safe_scripts": ["banner", "http-title", "ssl-cert"],
        "alerts": [
            {
                "name": "weak-cipher",
                "severity": "medium",
                "detail": "TLS endpoint allows weak ciphers.",
            }
        ]
        if any(port in {443, 8443} for port, *_ in open_ports)
        else [],
    }
    parsed_output = {
        "host": {
            "target": target_value,
            "status": "up",
            "latency_ms": round(rng.uniform(0.4, 2.8), 3),
            "os_guess": os_guess,
        },
        "ports": parsed_ports,
        "summary": {
            "open_ports": open_port_count,
            "closed_ports": closed_ports,
            "filtered_ports": filtered_ports,
        },
    }

    result_summary = {
        "critical_findings": sum(1 for row in open_ports if row[4] == ScanPortResult.RiskLevel.HIGH),
        "high_risk_ports": [row[0] for row in open_ports if row[4] == ScanPortResult.RiskLevel.HIGH],
        "service_count": len({row[2] for row in open_ports}),
    }

    result, _created = ScanResult.objects.update_or_create(
        execution=execution,
        defaults={
            "target_snapshot": target_value,
            "host_status": ScanResult.HostStatus.UP,
            "total_open_ports": open_port_count,
            "total_closed_ports": closed_ports,
            "total_filtered_ports": filtered_ports,
            "total_services_detected": len({row[2] for row in open_ports}),
            "os_guess": os_guess,
            "raw_output_text": raw_output_text,
            "raw_output_xml": "<nmaprun><host>simulated</host></nmaprun>",
            "parsed_output_json": parsed_output,
            "traceroute_data_json": traceroute,
            "script_output_json": script_output,
            "result_summary": result_summary,
            "generated_at": timezone.now(),
        },
    )

    result.port_results.all().delete()
    ScanPortResult.objects.bulk_create(
        [
            ScanPortResult(
                result=result,
                port=port,
                protocol=protocol,
                state="open",
                service_name=service,
                service_version=version,
                risk_level=risk,
                extra_data_json={"source": "simulator"},
            )
            for port, protocol, service, version, risk in open_ports
        ]
    )
    return result


def get_previous_result(result: ScanResult, *, user=None) -> ScanResult | None:
    execution = result.execution
    target = execution.scan_request.target
    queryset = (
        ScanResult.objects.select_related("execution__scan_request__target")
        .filter(execution__scan_request__target=target, generated_at__lt=result.generated_at)
        .order_by("-generated_at")
    )
    if user is not None:
        queryset = data_visibility_service.get_user_visible_results(user, queryset=queryset)
    return queryset.first()


def _state_bucket(state: str) -> str:
    value = (state or "").strip().lower()
    if value == "open":
        return "open"
    if value == "closed":
        return "closed"
    if "filtered" in value:
        return "filtered"
    return "other"


def _safe_int(value, fallback: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def build_result_detail_context(result: ScanResult, *, user=None) -> dict:
    port_rows = list(result.port_results.all().order_by("port", "protocol"))
    service_rows = [row for row in port_rows if row.service_name]
    version_rows = [row for row in port_rows if row.service_version]
    traceroute_rows = result.traceroute_data_json if isinstance(result.traceroute_data_json, list) else []
    script_rows = result.script_output_json if isinstance(result.script_output_json, dict) else {}
    parsed_output = result.parsed_output_json if isinstance(result.parsed_output_json, dict) else {}
    parsed_summary = parsed_output.get("summary", {}) if isinstance(parsed_output, dict) else {}
    state_counts = {"open": 0, "closed": 0, "filtered": 0, "other": 0}
    protocols: set[str] = set()
    service_names: set[str] = set()
    host_markers: set[str] = set()
    for row in port_rows:
        state_counts[_state_bucket(row.state)] += 1
        if row.protocol:
            protocols.add(row.protocol.lower())
        if row.service_name:
            service_names.add(row.service_name.lower())
        if isinstance(row.extra_data_json, dict):
            host = (row.extra_data_json.get("host") or "").strip()
            if host:
                host_markers.add(host)

    summary_counts = {
        "table_port_rows": len(port_rows),
        "row_open_ports": state_counts["open"],
        "row_closed_ports": state_counts["closed"],
        "row_filtered_ports": state_counts["filtered"],
        "total_ports": _safe_int(parsed_summary.get("total_ports"), len(port_rows)),
        "open_ports": _safe_int(parsed_summary.get("open_ports"), state_counts["open"]),
        "closed_ports": _safe_int(parsed_summary.get("closed_ports"), state_counts["closed"]),
        "filtered_ports": _safe_int(parsed_summary.get("filtered_ports"), state_counts["filtered"]),
        "other_ports": state_counts["other"],
        "unique_services": len(service_names),
        "service_rows": len(service_rows),
        "version_rows": len(version_rows),
        "protocol_count": len(protocols),
        "protocols": sorted(protocols),
        "state_breakdown": state_counts,
    }
    return {
        "port_results": port_rows,
        "service_rows": service_rows,
        "version_rows": version_rows,
        "traceroute_rows": traceroute_rows,
        "script_rows": script_rows,
        "parsed_output": parsed_output,
        "summary_counts": summary_counts,
        "parser_warnings": result.parser_warnings_json if isinstance(result.parser_warnings_json, list) else [],
        "parser_validation": result.parser_validation_json if isinstance(result.parser_validation_json, dict) else {},
        "has_multi_host_rows": len(host_markers) > 1,
        "previous_result": get_previous_result(result, user=user),
    }


def build_host_detail_context(target: Target, *, user=None) -> dict:
    results = (
        ScanResult.objects.select_related("execution__scan_request", "execution__scan_request__profile")
        .filter(execution__scan_request__target=target)
        .order_by("-generated_at")
    )
    if user is not None:
        results = data_visibility_service.get_user_visible_results(user, queryset=results)
    latest_result = results.first()
    current_ports = latest_result.port_results.filter(state="open").order_by("port") if latest_result else []

    trend_rows = []
    for row in results[:12][::-1]:
        trend_rows.append(
            {
                "label": row.generated_at.strftime("%m-%d"),
                "open_ports": row.total_open_ports,
            }
        )

    return {
        "target": target,
        "latest_result": latest_result,
        "recent_results": results[:10],
        "current_ports": current_ports,
        "trend_rows": trend_rows,
    }
