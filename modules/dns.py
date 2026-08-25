"""
DNS module — runs dnsrecon for forward and reverse DNS enumeration.
Domain derivation uses Python subprocess instead of the original shell pipeline.
"""

from __future__ import annotations

import logging
import netutil
import subprocess
from typing import Optional

from config import Config
from models import Job, PortInfo
from modules import BaseModule

log = logging.getLogger(__name__)


class DnsModule(BaseModule):
    required_tools = ["dnsrecon"]

    def match(self, port: PortInfo) -> bool:
        return port.portid == "53" or port.name == "dns"

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        tool = config.tool("dnsrecon")
        if not tool:
            return []
        jobs: list[Job] = []

        tcp = port.protocol == "tcp"
        # Include port_key in descriptions so 53/tcp and 53/udp (which produce
        # different cmds — the tcp version adds --tcp) have distinct resume
        # keys. Without this, --resume would incorrectly skip the udp variant
        # after the tcp variant succeeded.
        key = f"{port.portid}/{port.protocol}"

        # Reverse DNS sweep of /24. IPv4-only: an IPv6 reverse zone uses nibble
        # (ip6.arpa) format and sweeping a /64 is infeasible, so skip it.
        if not netutil.is_ipv6(host):
            rdns_cmd = [tool, "-n", host, "-r", f"{host}/24"]
            if tcp:
                rdns_cmd.append("--tcp")
            jobs.append(Job(
                cmd=rdns_cmd,
                output_file=f"{netutil.safe_filename(host)}.misc.rdns",
                category="misc",
                host=host,
                description=f"dnsrecon reverse {host}/24 ({key})",
            ))

        # Forward DNS — resolve domain via PTR then run zone transfer attempt
        domain = _resolve_domain(host, tcp)
        if domain:
            fwd_cmd = [tool, "-a", "-n", host, "-d", domain]
            if tcp:
                fwd_cmd.append("--tcp")
            jobs.append(Job(
                cmd=fwd_cmd,
                output_file=f"{netutil.safe_filename(host)}.misc.dns",
                category="misc",
                host=host,
                description=f"dnsrecon forward {host} ({domain}) ({key})",
            ))

        return jobs


def _resolve_domain(host: str, tcp: bool) -> Optional[str]:
    """
    Reverse-resolve host → hostname, then extract the domain (last two labels).
    Replaces the original shell: $(host {hosttcp}{host} {host} | grep "domain.*pointer" | ...)
    """
    flags = ["-T"] if tcp else []
    try:
        result = subprocess.run(
            ["host"] + flags + [host],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in result.stdout.splitlines():
            if "domain" in line and "pointer" in line:
                # "X.in-addr.arpa domain name pointer hostname.example.com."
                ptr = line.split("pointer")[-1].strip().rstrip(".")
                parts = ptr.split(".")
                if len(parts) >= 2:
                    return ".".join(parts[-2:])
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log.debug(f"domain resolution failed for {host}: {e}")
    return None
