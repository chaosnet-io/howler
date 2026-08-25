"""
RDP module — protocol/security check via rdp-sec-check.

Checks RDP protocol version, NLA enforcement, encryption level, and
known downgrade/bypass vulnerabilities. Port 3389 is currently ignored
by every other module — this fills a common coverage gap.
"""

from __future__ import annotations

import netutil
from config import Config
from models import Job, PortInfo
from modules import BaseModule


class RdpModule(BaseModule):
    required_tools = ["rdp-sec-check"]

    def match(self, port: PortInfo) -> bool:
        return port.portid == "3389" or port.name == "ms-wbt-server"

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        tool = config.tool("rdp-sec-check")
        if not tool:
            return []
        return [Job(
            cmd=[tool, netutil.hostport(host, port.portid)],
            output_file=f"{netutil.safe_filename(host)}-{port.portid}.misc.rdp_sec_check",
            category="misc",
            host=host,
            description=f"rdp-sec-check {host}:{port.portid}",
        )]
