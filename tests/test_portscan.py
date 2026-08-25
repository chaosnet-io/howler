"""
Tests for scanner/portscan.py job builders and the masscan command builder in
scanner/discovery.py.

These pin the scan-shape toggles that the external profile flips (OS detection,
UDP, scan rate) and the scope-exclusion plumbing (--excludefile) into the actual
argv the tools are invoked with. A regression here silently changes what gets
scanned on a real engagement, so we assert on the command lists directly.
"""
from __future__ import annotations

from config import Config
from scanner import portscan
from scanner.discovery import _build_masscan_cmd


def _script_args(cmd: list[str]) -> str:
    return cmd[cmd.index("--script-args") + 1]


# ── TCP job ─────────────────────────────────────────────────────────────────

def test_tcp_job_internal_defaults_include_os_detect_and_nse_args():
    c = Config()
    job = portscan.tcp_scan_job("10.0.0.1", None, True, c)
    assert "-O" in job.cmd
    assert _script_args(job.cmd) == c.nse_script_args()
    assert "--excludefile" not in job.cmd


def test_tcp_job_omits_os_detect_when_disabled():
    c = Config()
    c.os_detect = False
    job = portscan.tcp_scan_job("10.0.0.1", None, True, c)
    assert "-O" not in job.cmd


def test_tcp_job_includes_excludefile_when_set():
    c = Config()
    c.exclude_file = "/tmp/scope.txt"
    job = portscan.tcp_scan_job("10.0.0.1", None, True, c)
    assert "--excludefile" in job.cmd
    assert job.cmd[job.cmd.index("--excludefile") + 1] == "/tmp/scope.txt"


def test_tcp_job_full_port_vs_top_ports():
    c = Config()
    full = portscan.tcp_scan_job("10.0.0.1", None, True, c)
    top = portscan.tcp_scan_job("10.0.0.1", None, False, c)
    assert "-p-" in full.cmd
    assert "--top-ports" in top.cmd and "-p-" not in top.cmd


def test_tcp_job_curated_ports_override_full_port_flag():
    """When nmap_tcp_ports is set (external profile), it wins over the
    full_port / top-1000 heuristic — even with full_port=True."""
    c = Config()
    c.nmap_tcp_ports = "22,80,443"
    job = portscan.tcp_scan_job("10.0.0.1", None, True, c)
    assert job.cmd[job.cmd.index("-p") + 1] == "22,80,443"
    assert "-p-" not in job.cmd
    assert "--top-ports" not in job.cmd


# ── UDP job ─────────────────────────────────────────────────────────────────

def test_udp_job_omits_os_detect_when_disabled():
    c = Config()
    c.os_detect = False
    job = portscan.udp_scan_job("10.0.0.1", None, c)
    assert "-O" not in job.cmd


def test_udp_job_includes_excludefile_when_set():
    c = Config()
    c.exclude_file = "/tmp/scope.txt"
    job = portscan.udp_scan_job("10.0.0.1", None, c)
    assert "--excludefile" in job.cmd


# ── External profile end-to-end into argv ───────────────────────────────────

def test_external_profile_flows_into_tcp_argv():
    c = Config()
    c.apply_external_profile()
    job = portscan.tcp_scan_job("10.0.0.1", None, True, c)
    assert "-O" not in job.cmd
    assert job.cmd[job.cmd.index("--max-rtt-timeout") + 1] == "1250ms"
    # DoS script dropped from the actual --script value.
    assert "smb-vuln-ms17-010" not in job.cmd[job.cmd.index("--script") + 1]


# ── masscan command ─────────────────────────────────────────────────────────

def test_masscan_cmd_excludefile_absent_by_default():
    c = Config()
    cmd = _build_masscan_cmd("masscan", ["10.0.0.0/24"], None, c)
    assert "--excludefile" not in cmd


def test_masscan_cmd_includes_excludefile_and_rate():
    c = Config()
    c.exclude_file = "/tmp/scope.txt"
    c.apply_external_profile()  # also caps the rate
    cmd = _build_masscan_cmd("masscan", ["10.0.0.0/24"], None, c)
    assert cmd[cmd.index("--excludefile") + 1] == "/tmp/scope.txt"
    assert cmd[cmd.index("--rate") + 1] == "300"


# ── IPv6 job shaping ─────────────────────────────────────────────────────────

def test_tcp_job_ipv6_adds_dash_6_and_sanitizes_output():
    c = Config()
    job = portscan.tcp_scan_job("2001:db8::5", None, True, c)
    assert "-6" in job.cmd
    # Output base is sanitized; the target host argument stays raw.
    assert job.cmd[job.cmd.index("-oA") + 1] == "2001_db8__5.tcp"
    assert job.output_file == "2001_db8__5.tcp.xml"
    assert job.host == "2001:db8::5"
    assert "2001:db8::5" in job.cmd


def test_udp_job_ipv6_adds_dash_6_and_sanitizes_output():
    c = Config()
    job = portscan.udp_scan_job("2001:db8::5", None, c)
    assert "-6" in job.cmd
    assert job.cmd[job.cmd.index("-oA") + 1] == "2001_db8__5.udp"
    assert job.output_file == "2001_db8__5.udp.xml"


def test_tcp_job_ipv4_unchanged_no_dash_6():
    c = Config()
    job = portscan.tcp_scan_job("10.0.0.1", None, True, c)
    assert "-6" not in job.cmd
    assert job.cmd[job.cmd.index("-oA") + 1] == "10.0.0.1.tcp"
    assert job.output_file == "10.0.0.1.tcp.xml"
