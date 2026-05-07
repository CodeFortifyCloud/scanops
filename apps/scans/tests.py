from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from django.test import TestCase

from apps.scans.models import ScanExecution, ScanProfile, ScanRequest, ScanResult
from apps.scans.services.nmap_execution_service import run_execution_with_nmap
from apps.scans.services.nmap_parser import parse_nmap_outputs
from apps.scans.services.result_service import build_result_detail_context
from apps.targets.models import Target


SAMPLE_STDOUT = """Starting Nmap 7.94 ( https://nmap.org ) at 2026-05-07 16:55 +06
Nmap scan report for 127.0.0.1
Host is up (0.0020s latency).
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 9.6
80/tcp   filtered http
53/udp   closed   domain
Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds
"""

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX - 127.0.0.1">
  <host>
    <status state="up" reason="syn-ack" reason_ttl="64"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <extraports state="closed" count="997"/>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ssh" product="OpenSSH" version="9.6"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="filtered" reason="no-response"/>
        <service name="http"/>
      </port>
      <port protocol="udp" portid="53">
        <state state="closed" reason="port-unreach"/>
        <service name="domain"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class NmapParserTests(TestCase):
    def test_xml_parser_keeps_port_states_and_counts_in_sync(self):
        parsed = parse_nmap_outputs(
            raw_output_text=SAMPLE_STDOUT,
            raw_output_xml=SAMPLE_XML,
            target_snapshot="127.0.0.1",
        )

        self.assertEqual(parsed.host_status, "up")
        self.assertEqual(len(parsed.ports), 3)
        states = {(row.port, row.protocol): row.state for row in parsed.ports}
        self.assertEqual(states[(22, "tcp")], "open")
        self.assertEqual(states[(80, "tcp")], "filtered")
        self.assertEqual(states[(53, "udp")], "closed")
        self.assertTrue(parsed.validation["port_count_match"])
        self.assertEqual(parsed.validation["raw_port_rows"], 3)
        self.assertEqual(parsed.validation["parsed_port_rows"], 3)
        self.assertTrue(parsed.validation["xml_parse_success"])
        self.assertEqual(parsed.parsed_output["summary"]["total_ports"], 1000)
        self.assertEqual(parsed.parsed_output["summary"]["closed_ports"], 998)

    def test_parser_falls_back_to_raw_output_when_xml_missing(self):
        parsed = parse_nmap_outputs(
            raw_output_text=SAMPLE_STDOUT,
            raw_output_xml="",
            target_snapshot="127.0.0.1",
        )
        self.assertTrue(parsed.validation["fallback_used"])
        self.assertEqual(len(parsed.ports), 3)
        self.assertGreaterEqual(len(parsed.warnings), 1)


class ResultDetailContextTests(TestCase):
    def setUp(self):
        self.target = Target.objects.create(
            name="Localhost",
            target_type=Target.TargetType.IP,
            target_value="127.0.0.1",
            status=Target.Status.ACTIVE,
        )
        self.profile = ScanProfile.objects.create(
            name="Test Profile",
            scan_type=ScanProfile.ScanType.TOP_100,
            timing_profile=ScanProfile.TimingProfile.NORMAL,
            is_active=True,
        )
        self.request = ScanRequest.objects.create(
            target=self.target,
            profile=self.profile,
            scan_type=self.profile.scan_type,
            timing_profile=self.profile.timing_profile,
            status=ScanRequest.Status.PENDING,
        )
        self.execution = ScanExecution.objects.create(
            scan_request=self.request,
            status=ScanExecution.Status.COMPLETED,
            queue_status=ScanExecution.QueueStatus.DONE,
            progress_percent=100,
        )
        self.result = ScanResult.objects.create(
            execution=self.execution,
            target_snapshot=self.target.target_value,
            host_status=ScanResult.HostStatus.UP,
            total_open_ports=99,  # intentionally stale/wrong
            total_closed_ports=99,  # intentionally stale/wrong
            total_filtered_ports=99,  # intentionally stale/wrong
            total_services_detected=99,  # intentionally stale/wrong
        )
        self.result.port_results.create(port=22, protocol="tcp", state="open", service_name="ssh", service_version="OpenSSH")
        self.result.port_results.create(port=53, protocol="udp", state="closed", service_name="domain", service_version="")
        self.result.port_results.create(port=443, protocol="tcp", state="filtered", service_name="https", service_version="")

    def test_detail_context_counters_come_from_port_rows(self):
        context = build_result_detail_context(self.result)
        summary = context["summary_counts"]
        self.assertEqual(summary["total_ports"], 3)
        self.assertEqual(summary["open_ports"], 1)
        self.assertEqual(summary["closed_ports"], 1)
        self.assertEqual(summary["filtered_ports"], 1)
        self.assertEqual(summary["unique_services"], 3)
        self.assertEqual(summary["protocol_count"], 2)

    def test_detail_context_prefers_parsed_summary_when_available(self):
        self.result.parsed_output_json = {
            "summary": {
                "total_ports": 1000,
                "open_ports": 1,
                "closed_ports": 998,
                "filtered_ports": 1,
            }
        }
        self.result.save(update_fields=["parsed_output_json", "updated_at"])
        context = build_result_detail_context(self.result)
        summary = context["summary_counts"]
        self.assertEqual(summary["total_ports"], 1000)
        self.assertEqual(summary["open_ports"], 1)
        self.assertEqual(summary["closed_ports"], 998)
        self.assertEqual(summary["filtered_ports"], 1)
        self.assertEqual(summary["table_port_rows"], 3)


class NmapExecutionPipelineTests(TestCase):
    def setUp(self):
        self.target = Target.objects.create(
            name="Localhost",
            target_type=Target.TargetType.IP,
            target_value="127.0.0.1",
            status=Target.Status.ACTIVE,
        )
        self.profile = ScanProfile.objects.create(
            name="Execution Profile",
            scan_type=ScanProfile.ScanType.TOP_100,
            timing_profile=ScanProfile.TimingProfile.NORMAL,
            is_active=True,
        )
        self.request = ScanRequest.objects.create(
            target=self.target,
            profile=self.profile,
            scan_type=self.profile.scan_type,
            timing_profile=self.profile.timing_profile,
            status=ScanRequest.Status.PENDING,
            enable_service_detection=True,
            enable_version_detection=True,
        )
        self.execution = ScanExecution.objects.create(
            scan_request=self.request,
            status=ScanExecution.Status.QUEUED,
            queue_status=ScanExecution.QueueStatus.WAITING,
        )

    @patch("apps.scans.services.nmap_execution_service.subprocess.run")
    def test_execution_stores_raw_and_parsed_data_from_real_pipeline(self, mocked_run):
        def _fake_run(command, capture_output, text, check, timeout):
            xml_path = command[command.index("-oX") + 1]
            Path(xml_path).write_text(SAMPLE_XML, encoding="utf-8")
            return subprocess.CompletedProcess(
                args=command,
                returncode=0,
                stdout=SAMPLE_STDOUT,
                stderr="",
            )

        mocked_run.side_effect = _fake_run

        result = run_execution_with_nmap(self.execution, worker_name="test-worker", timeout_seconds=30)
        self.execution.refresh_from_db()
        result.refresh_from_db()

        self.assertEqual(self.execution.status, ScanExecution.Status.COMPLETED)
        self.assertIn("nmap", result.executed_command.lower())
        self.assertEqual(result.raw_output_text.strip(), SAMPLE_STDOUT.strip())
        self.assertEqual(result.raw_error_output, "")
        self.assertEqual(result.port_results.count(), 3)
        self.assertEqual(result.total_open_ports, 1)
        self.assertEqual(result.total_closed_ports, 998)
        self.assertEqual(result.total_filtered_ports, 1)
