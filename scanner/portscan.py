"""
Nmap TCP/UDP Job builders and hostname resolution.
"""

from __future__ import annotations

import logging
import subprocess
from typing import Optional

from config import Config
from models import Job

log = logging.getLogger(__name__)


def tcp_scan_job(host: str, iface: Optional[str], full_port: bool, config: Config) -> Job:
    """Build a nmap TCP scan Job for a single host."""
    nmap_bin = config.tool("nmap") or "nmap"

    nse_args = (
        f'http-put.url="/",http-put.file="/etc/timezone",'
        f'cmd="whoami",httpspider.maxpagecount=100'
    )

    cmd = [
        nmap_bin,
        "-v0", "-n", "-Pn", "-O", "-sSV",
        *([ "-p-"] if full_port else ["--top-ports", "1000"]),
        "--script", config.nmap_nse_tcp,
        "--script-args", nse_args,
        "--version-intensity", str(config.nmap_version_intensity),
        "--max-retries", str(config.nmap_max_retries),
        "--max-rtt-timeout", config.nmap_max_rtt_timeout,
        "--max-scan-delay", config.nmap_max_scan_delay,
        "--host-timeout", f"{config.task_timeout // 60}m",
        "--open",
        "-oA", f"{host}.tcp",
        *([ "-e", iface] if iface else []),
        host,
    ]
    return Job(
        cmd=cmd,
        output_file=f"{host}.tcp.xml",
        category="xml",
        host=host,
        timeout=config.task_timeout,
        description=f"nmap TCP {'full' if full_port else 'top-1k'} {host}",
    )


def udp_scan_job(host: str, iface: Optional[str], config: Config) -> Job:
    """Build a nmap UDP scan Job for a single host."""
    nmap_bin = config.tool("nmap") or "nmap"

    cmd = [
        nmap_bin,
        "-v0", "-n", "-Pn", "-O", "-sUV",
        "-p", config.nmap_udp_ports,
        "--script", config.nmap_nse_udp,
        "--version-intensity", str(config.nmap_version_intensity),
        "--max-retries", str(config.nmap_max_retries),
        "--max-rtt-timeout", config.nmap_max_rtt_timeout,
        "--max-scan-delay", config.nmap_max_scan_delay,
        "--host-timeout", f"{config.task_timeout // 60}m",
        "--open",
        "-oA", f"{host}.udp",
        *([ "-e", iface] if iface else []),
        host,
    ]
    return Job(
        cmd=cmd,
        output_file=f"{host}.udp.xml",
        category="xml",
        host=host,
        timeout=config.task_timeout,
        description=f"nmap UDP {host}",
    )


def resolve_hostname(host: str) -> Optional[str]:
    """
    Reverse-resolve an IP to a hostname via `host` command.
    Returns the hostname string or None if not found.
    """
    try:
        result = subprocess.run(
            ["host", host],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in result.stdout.splitlines():
            if "pointer" in line:
                # e.g. "1.0.168.192.in-addr.arpa domain name pointer myhost.example.com."
                parts = line.split("pointer")
                if len(parts) > 1:
                    return parts[1].strip().rstrip(".")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log.debug(f"hostname resolution failed for {host}: {e}")
    return None
