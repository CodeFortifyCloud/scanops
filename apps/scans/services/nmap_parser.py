from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from xml.etree import ElementTree


PORT_ROW_PATTERN = re.compile(
    r"^\s*(?P<port>\d+)\/(?P<protocol>[a-zA-Z0-9]+)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<service>\S+)"
    r"(?:\s+(?P<version>.+))?$"
)
LATENCY_PATTERN = re.compile(r"\((?P<latency>[\d.]+)s latency\)", re.IGNORECASE)
NOT_SHOWN_PATTERN = re.compile(
    r"^Not shown:\s+(?P<count>\d+)\s+(?P<state>[a-zA-Z|]+)\s+ports?",
    re.IGNORECASE,
)
ALL_IGNORED_PATTERN = re.compile(
    r"^All\s+(?P<count>\d+)\s+scanned ports .*?\((?P<states>.+)\)",
    re.IGNORECASE,
)


@dataclass(slots=True)
class ParsedPortRow:
    host: str
    port: int
    protocol: str
    state: str
    service_name: str
    service_version: str
    extra_data: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ParsedNmapResult:
    host_status: str
    os_guess: str
    latency_ms: float | None
    ports: list[ParsedPortRow] = field(default_factory=list)
    traceroute_rows: list[dict[str, Any]] = field(default_factory=list)
    script_output: dict[str, Any] = field(default_factory=dict)
    parsed_output: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    validation: dict[str, Any] = field(default_factory=dict)


def _state_bucket(state: str) -> str:
    value = (state or "").strip().lower()
    if value == "open":
        return "open"
    if value == "closed":
        return "closed"
    if "filtered" in value:
        return "filtered"
    return "other"


def _extract_raw_port_rows(raw_output: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in (raw_output or "").splitlines():
        match = PORT_ROW_PATTERN.match(line)
        if not match:
            continue
        rows.append(
            {
                "port": match.group("port"),
                "protocol": (match.group("protocol") or "").lower(),
                "state": (match.group("state") or "").lower(),
                "service": match.group("service") or "",
                "version": (match.group("version") or "").strip(),
            }
        )
    return rows


def _parse_times_latency_ms(host_element) -> float | None:
    times_element = host_element.find("times")
    if times_element is None:
        return None
    # Nmap srtt is stored in microseconds in XML.
    srtt = (times_element.attrib.get("srtt") or "").strip()
    if not srtt.isdigit():
        return None
    try:
        return round(int(srtt) / 1000.0, 3)
    except ValueError:
        return None


def _build_service_version(service_element) -> str:
    if service_element is None:
        return ""
    product = (service_element.attrib.get("product") or "").strip()
    version = (service_element.attrib.get("version") or "").strip()
    extrainfo = (service_element.attrib.get("extrainfo") or "").strip()

    parts: list[str] = []
    if product:
        parts.append(product)
    if version:
        parts.append(version)
    if extrainfo:
        parts.append(f"({extrainfo})")
    return " ".join(parts).strip()


def _highest_accuracy_os_match(host_element) -> str:
    best_name = ""
    best_accuracy = -1
    for row in host_element.findall("os/osmatch"):
        name = (row.attrib.get("name") or "").strip()
        accuracy_raw = (row.attrib.get("accuracy") or "").strip()
        try:
            accuracy = int(accuracy_raw)
        except ValueError:
            accuracy = 0
        if name and accuracy >= best_accuracy:
            best_name = name
            best_accuracy = accuracy
    return best_name


def _host_label_from_xml(host_element, fallback_target: str) -> str:
    for addr in host_element.findall("address"):
        value = (addr.attrib.get("addr") or "").strip()
        if value:
            return value
    hostname = host_element.find("hostnames/hostname")
    if hostname is not None:
        value = (hostname.attrib.get("name") or "").strip()
        if value:
            return value
    return fallback_target


def _parse_scripts(host_element) -> dict[str, Any]:
    host_scripts: list[dict[str, str]] = []
    for script in host_element.findall("hostscript/script"):
        script_id = (script.attrib.get("id") or "").strip()
        output = (script.attrib.get("output") or "").strip()
        if script_id or output:
            host_scripts.append({"id": script_id, "output": output})

    port_scripts: list[dict[str, Any]] = []
    for port in host_element.findall("ports/port"):
        protocol = (port.attrib.get("protocol") or "").strip().lower()
        port_id_raw = (port.attrib.get("portid") or "").strip()
        if not port_id_raw.isdigit():
            continue
        port_id = int(port_id_raw)
        for script in port.findall("script"):
            script_id = (script.attrib.get("id") or "").strip()
            output = (script.attrib.get("output") or "").strip()
            if not script_id and not output:
                continue
            port_scripts.append(
                {
                    "port": port_id,
                    "protocol": protocol,
                    "id": script_id,
                    "output": output,
                }
            )
    return {
        "host_scripts": host_scripts,
        "port_scripts": port_scripts,
    }


def _parse_traceroute(host_element) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    trace = host_element.find("trace")
    if trace is None:
        return rows
    for hop in trace.findall("hop"):
        ttl_raw = (hop.attrib.get("ttl") or "").strip()
        ipaddr = (hop.attrib.get("ipaddr") or "").strip()
        hostname = (hop.attrib.get("host") or "").strip()
        rtt = (hop.attrib.get("rtt") or "").strip()
        ttl = int(ttl_raw) if ttl_raw.isdigit() else None
        rows.append(
            {
                "hop": ttl,
                "host": hostname or ipaddr,
                "ipaddr": ipaddr,
                "latency_ms": rtt,
            }
        )
    return rows


def _aggregate_host_status(states: list[str]) -> str:
    normalized = [(state or "").strip().lower() for state in states if state]
    if not normalized:
        return "unknown"
    has_up = any(state == "up" for state in normalized)
    has_down = any(state == "down" for state in normalized)
    if has_up and has_down:
        return "partial"
    if has_up:
        return "up"
    if has_down:
        return "down"
    return "unknown"


def _ports_summary(ports: list[ParsedPortRow]) -> dict[str, int]:
    summary = {"open": 0, "closed": 0, "filtered": 0, "other": 0}
    for row in ports:
        summary[_state_bucket(row.state)] += 1
    return summary


def _parse_xml_output(raw_xml: str, target_snapshot: str) -> ParsedNmapResult:
    root = ElementTree.fromstring(raw_xml)
    hosts = root.findall("host")

    all_ports: list[ParsedPortRow] = []
    host_rows: list[dict[str, Any]] = []
    host_states: list[str] = []
    traceroute_rows: list[dict[str, Any]] = []
    all_scripts: list[dict[str, Any]] = []
    host_scripts: list[dict[str, Any]] = []
    os_candidates: list[str] = []
    latencies: list[float] = []
    extraports_by_state: dict[str, int] = {}

    for host in hosts:
        host_state = (host.find("status").attrib.get("state", "") if host.find("status") is not None else "").lower()
        host_states.append(host_state)
        host_label = _host_label_from_xml(host, target_snapshot)
        latency_ms = _parse_times_latency_ms(host)
        if latency_ms is not None:
            latencies.append(latency_ms)
        os_guess = _highest_accuracy_os_match(host)
        if os_guess:
            os_candidates.append(os_guess)

        host_ports: list[dict[str, Any]] = []
        ports_section = host.find("ports")
        if ports_section is not None:
            for extra in ports_section.findall("extraports"):
                state = (extra.attrib.get("state") or "").strip().lower()
                count_raw = (extra.attrib.get("count") or "").strip()
                if state and count_raw.isdigit():
                    extraports_by_state[state] = extraports_by_state.get(state, 0) + int(count_raw)

            for port in ports_section.findall("port"):
                protocol = (port.attrib.get("protocol") or "").strip().lower()
                port_id_raw = (port.attrib.get("portid") or "").strip()
                if not port_id_raw.isdigit():
                    continue

                state_element = port.find("state")
                state = (state_element.attrib.get("state") if state_element is not None else "unknown") or "unknown"
                state = state.strip().lower()

                service_element = port.find("service")
                service_name = ""
                if service_element is not None:
                    service_name = (service_element.attrib.get("name") or "").strip()
                service_version = _build_service_version(service_element)

                port_scripts = []
                for script in port.findall("script"):
                    script_id = (script.attrib.get("id") or "").strip()
                    output = (script.attrib.get("output") or "").strip()
                    if script_id or output:
                        port_scripts.append({"id": script_id, "output": output})
                        all_scripts.append(
                            {
                                "port": int(port_id_raw),
                                "protocol": protocol,
                                "id": script_id,
                                "output": output,
                            }
                        )

                cpe_rows = [
                    cpe.text.strip()
                    for cpe in port.findall("service/cpe")
                    if cpe.text and cpe.text.strip()
                ]
                reason = ""
                reason_ttl = ""
                if state_element is not None:
                    reason = (state_element.attrib.get("reason") or "").strip()
                    reason_ttl = (state_element.attrib.get("reason_ttl") or "").strip()

                extra_data = {
                    "host": host_label,
                    "reason": reason,
                    "reason_ttl": reason_ttl,
                    "tunnel": (service_element.attrib.get("tunnel") or "").strip() if service_element is not None else "",
                    "method": (service_element.attrib.get("method") or "").strip() if service_element is not None else "",
                    "conf": (service_element.attrib.get("conf") or "").strip() if service_element is not None else "",
                    "cpes": cpe_rows,
                    "scripts": port_scripts,
                }

                parsed_row = ParsedPortRow(
                    host=host_label,
                    port=int(port_id_raw),
                    protocol=protocol or "tcp",
                    state=state,
                    service_name=service_name,
                    service_version=service_version,
                    extra_data=extra_data,
                )
                all_ports.append(parsed_row)
                host_ports.append(
                    {
                        "port": parsed_row.port,
                        "protocol": parsed_row.protocol,
                        "state": parsed_row.state,
                        "service": parsed_row.service_name,
                        "version": parsed_row.service_version,
                    }
                )

        host_script_block = _parse_scripts(host)
        if host_script_block["host_scripts"]:
            host_scripts.extend(host_script_block["host_scripts"])

        host_trace_rows = _parse_traceroute(host)
        traceroute_rows.extend(host_trace_rows)

        host_rows.append(
            {
                "host": host_label,
                "status": host_state or "unknown",
                "latency_ms": latency_ms,
                "os_guess": os_guess,
                "ports": host_ports,
                "traceroute": host_trace_rows,
                "host_scripts": host_script_block["host_scripts"],
            }
        )

    host_status = _aggregate_host_status(host_states)
    summary = _ports_summary(all_ports)
    open_total = summary["open"] + extraports_by_state.get("open", 0)
    closed_total = summary["closed"] + extraports_by_state.get("closed", 0)
    filtered_total = summary["filtered"] + extraports_by_state.get("filtered", 0)
    total_ports = len(all_ports) + sum(extraports_by_state.values())

    parsed_output = {
        "scanner": root.attrib.get("scanner", "nmap"),
        "args": root.attrib.get("args", ""),
        "started_at": root.attrib.get("startstr", ""),
        "hosts": host_rows,
        "summary": {
            "hosts_total": len(host_rows),
            "hosts_up": sum(1 for row in host_rows if row["status"] == "up"),
            "hosts_down": sum(1 for row in host_rows if row["status"] == "down"),
            "total_ports": total_ports,
            "open_ports": open_total,
            "closed_ports": closed_total,
            "filtered_ports": filtered_total,
            "state_breakdown": summary,
            "extraports": extraports_by_state,
        },
    }

    script_output = {
        "host_scripts": host_scripts,
        "port_scripts": all_scripts,
        "safe_scripts": sorted({row["id"] for row in all_scripts if row.get("id")}),
        "alerts": [],
    }

    os_guess = os_candidates[0] if os_candidates else ""
    latency_ms = round(sum(latencies) / len(latencies), 3) if latencies else None
    return ParsedNmapResult(
        host_status=host_status,
        os_guess=os_guess,
        latency_ms=latency_ms,
        ports=all_ports,
        traceroute_rows=traceroute_rows,
        script_output=script_output,
        parsed_output=parsed_output,
    )


def _parse_raw_output_fallback(raw_output: str, target_snapshot: str) -> ParsedNmapResult:
    rows = _extract_raw_port_rows(raw_output)
    ports: list[ParsedPortRow] = []
    warnings: list[str] = []
    host_status = "unknown"
    os_guess = ""
    latency_ms: float | None = None

    not_shown_counts: dict[str, int] = {}
    for line in (raw_output or "").splitlines():
        normalized = line.strip()
        if "Host is up" in normalized:
            host_status = "up"
            latency_match = LATENCY_PATTERN.search(normalized)
            if latency_match:
                try:
                    latency_ms = round(float(latency_match.group("latency")) * 1000, 3)
                except ValueError:
                    latency_ms = None
        elif "Host seems down" in normalized or "0 hosts up" in normalized:
            host_status = "down"
        elif normalized.startswith("Running:"):
            os_guess = normalized.split("Running:", maxsplit=1)[1].strip()
        elif normalized.startswith("OS details:") and not os_guess:
            os_guess = normalized.split("OS details:", maxsplit=1)[1].strip()

        match = NOT_SHOWN_PATTERN.match(normalized)
        if match:
            state = (match.group("state") or "").strip().lower()
            count = int(match.group("count"))
            not_shown_counts[state] = not_shown_counts.get(state, 0) + count
            continue

        ignored_match = ALL_IGNORED_PATTERN.match(normalized)
        if ignored_match:
            count = int(ignored_match.group("count"))
            states = ignored_match.group("states")
            state = "filtered"
            if "closed" in states.lower():
                state = "closed"
            not_shown_counts[state] = not_shown_counts.get(state, 0) + count

    for row in rows:
        try:
            port_number = int(row["port"])
        except ValueError:
            warnings.append(f"Skipped malformed port row: {row}")
            continue
        ports.append(
            ParsedPortRow(
                host=target_snapshot,
                port=port_number,
                protocol=row["protocol"] or "tcp",
                state=row["state"] or "unknown",
                service_name=row["service"],
                service_version=row["version"],
                extra_data={"host": target_snapshot, "source": "raw_fallback"},
            )
        )

    summary = _ports_summary(ports)
    total_ports = len(ports) + sum(not_shown_counts.values())
    parsed_output = {
        "scanner": "nmap",
        "args": "",
        "hosts": [
            {
                "host": target_snapshot,
                "status": host_status,
                "latency_ms": latency_ms,
                "os_guess": os_guess,
                "ports": [
                    {
                        "port": row.port,
                        "protocol": row.protocol,
                        "state": row.state,
                        "service": row.service_name,
                        "version": row.service_version,
                    }
                    for row in ports
                ],
            }
        ],
        "summary": {
            "hosts_total": 1,
            "hosts_up": 1 if host_status == "up" else 0,
            "hosts_down": 1 if host_status == "down" else 0,
            "total_ports": total_ports,
            "open_ports": summary["open"] + not_shown_counts.get("open", 0),
            "closed_ports": summary["closed"] + not_shown_counts.get("closed", 0),
            "filtered_ports": summary["filtered"] + not_shown_counts.get("filtered", 0),
            "state_breakdown": summary,
            "extraports": not_shown_counts,
        },
    }
    return ParsedNmapResult(
        host_status=host_status,
        os_guess=os_guess,
        latency_ms=latency_ms,
        ports=ports,
        traceroute_rows=[],
        script_output={"host_scripts": [], "port_scripts": [], "safe_scripts": [], "alerts": []},
        parsed_output=parsed_output,
        warnings=warnings,
    )


def parse_nmap_outputs(
    *,
    raw_output_text: str,
    raw_output_xml: str,
    target_snapshot: str,
) -> ParsedNmapResult:
    warnings: list[str] = []
    raw_port_rows = _extract_raw_port_rows(raw_output_text)
    raw_port_count = len(raw_port_rows)
    xml_parse_success = False
    fallback_used = False

    parsed = ParsedNmapResult(host_status="unknown", os_guess="", latency_ms=None)
    if raw_output_xml.strip():
        try:
            parsed = _parse_xml_output(raw_output_xml, target_snapshot)
            xml_parse_success = True
        except ElementTree.ParseError as exc:
            warnings.append(f"Nmap XML parse error: {exc}")
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Unexpected XML parsing error: {exc}")

    if not xml_parse_success:
        fallback_used = True
        parsed = _parse_raw_output_fallback(raw_output_text, target_snapshot)
        warnings.append("Used raw output fallback parser because XML data was missing or invalid.")

    parsed_port_count = len(parsed.ports)
    skipped_rows = max(raw_port_count - parsed_port_count, 0)
    port_count_match = raw_port_count == parsed_port_count or raw_port_count == 0
    if not port_count_match:
        warnings.append(
            f"Port count mismatch: raw output has {raw_port_count} table rows, parser persisted {parsed_port_count} rows."
        )

    parsed.warnings.extend(warnings)
    parsed.validation = {
        "raw_port_rows": raw_port_count,
        "parsed_port_rows": parsed_port_count,
        "skipped_rows": skipped_rows,
        "port_count_match": port_count_match,
        "xml_parse_success": xml_parse_success,
        "fallback_used": fallback_used,
    }
    return parsed
