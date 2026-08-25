"""
SNMP module — community string brute via onesixtyone.
Replaces MSF snmp_login (drops the msfconsole dependency; onesixtyone is a
single-purpose Kali-packaged tool that's much faster to spawn than msfconsole).
"""

from __future__ import annotations

import netutil
from config import Config
from models import Job, PortInfo
from modules import BaseModule


class SnmpModule(BaseModule):
    required_tools = ["onesixtyone"]

    def match(self, port: PortInfo) -> bool:
        return port.portid == "161" or port.name == "snmp"

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        tool = config.tool("onesixtyone")
        if not tool or not config.snmp_dict.exists():
            return []
        return [Job(
            cmd=[
                tool,
                "-c", str(config.snmp_dict),
                host,
            ],
            output_file=f"{netutil.safe_filename(host)}-{port.portid}.misc.snmp",
            category="misc",
            host=host,
            description=f"onesixtyone {host}:{port.portid}",
        )]
