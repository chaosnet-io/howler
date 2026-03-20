"""
IKE/IPSec module — probes IKEv1/IKEv2 and NAT-T variants via ike-scan.
"""

from __future__ import annotations

from config import Config
from models import Job, PortInfo
from modules import BaseModule


class IkeModule(BaseModule):
    required_tools = ["ike-scan"]

    def match(self, port: PortInfo) -> bool:
        return port.name in {"isakmp", "nat-t-ike"} or port.portid == "500"

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        tool = config.tool("ike-scan")
        if not tool:
            return []

        jobs: list[Job] = []
        nat_t = port.name == "nat-t-ike" or port.portid == "4500"

        if nat_t:
            jobs.append(Job(
                cmd=[tool, "-A", "-M", "-P", "-n", "esttest", "--nat-t", host],
                output_file=f"{host}.misc.nat-ike",
                category="misc",
                host=host,
                description=f"ike-scan NAT-T IKEv1 {host}",
            ))
            jobs.append(Job(
                cmd=[tool, "-2", "-M", "--nat-t", host],
                output_file=f"{host}.misc.nat-ike",
                category="misc",
                host=host,
                description=f"ike-scan NAT-T IKEv2 {host}",
            ))
        else:
            jobs.append(Job(
                cmd=[tool, "-A", "-M", "-P", "-n", "esttest", host],
                output_file=f"{host}.misc.ike",
                category="misc",
                host=host,
                description=f"ike-scan IKEv1 {host}",
            ))
            jobs.append(Job(
                cmd=[tool, "-2", "-M", host],
                output_file=f"{host}.misc.ike",
                category="misc",
                host=host,
                description=f"ike-scan IKEv2 {host}",
            ))

        return jobs
