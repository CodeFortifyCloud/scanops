from __future__ import annotations

from apps.scans.models import ScanProfile, ScanRequest


TIMING_MAP = {
    ScanProfile.TimingProfile.NORMAL: "3",
    ScanProfile.TimingProfile.BALANCED: "4",
    ScanProfile.TimingProfile.FAST: "5",
}


def _default_ports_for_scan_type(scan_type: str) -> list[str]:
    if scan_type == ScanProfile.ScanType.HOST_DISCOVERY:
        return []
    if scan_type == ScanProfile.ScanType.QUICK_TCP:
        return ["--top-ports", "100"]
    if scan_type == ScanProfile.ScanType.TOP_100:
        return ["--top-ports", "100"]
    if scan_type == ScanProfile.ScanType.TOP_1000:
        return ["--top-ports", "1000"]
    if scan_type == ScanProfile.ScanType.SERVICE_DETECTION:
        return ["--top-ports", "1000"]
    return ["--top-ports", "1000"]


def build_nmap_command(
    scan_request: ScanRequest,
    *,
    xml_output_path: str,
    nmap_binary: str = "nmap",
) -> list[str]:
    command: list[str] = [nmap_binary]
    command.extend(["-oX", xml_output_path])

    if scan_request.scan_type == ScanProfile.ScanType.HOST_DISCOVERY:
        command.append("-sn")
    elif not scan_request.enable_host_discovery:
        command.append("-Pn")

    if not scan_request.enable_dns_resolution:
        command.append("-n")

    timing_value = TIMING_MAP.get(scan_request.timing_profile, "3")
    command.append(f"-T{timing_value}")

    if scan_request.enable_service_detection or scan_request.enable_version_detection:
        command.append("-sV")

    if scan_request.enable_os_detection:
        command.append("-O")

    if scan_request.enable_traceroute:
        command.append("--traceroute")

    port_input = (scan_request.port_input or "").strip()
    if port_input and scan_request.scan_type != ScanProfile.ScanType.HOST_DISCOVERY:
        command.extend(["-p", port_input])
    else:
        command.extend(_default_ports_for_scan_type(scan_request.scan_type))

    command.append(scan_request.target.target_value)
    return command
