"""
IPMI module — probes IPMI version and cipher info via ipmitool.

Replaces 3 MSF modules (ipmi_version, ipmi_dumphashes, ipmi_cipher_zero).
- Version + cipher info: ``ipmitool -I lan -H <host> lan print`` covers both.
- Hash dump (CVE-2013-4786 RAKP): dropped per project policy — no widely-
  packaged standalone equivalent exists. Use the ipmi-cipher-zero NSE
  (already in nmap nse_udp) for cipher-zero detection instead.

SMT IPMI exposure on port 49152 is now handled by HttpModule — whatweb /
wafw00f / gowitness fire there automatically since nmap reports it as http.
"""

from __future__ import annotations

from config import Config
from models import Job, PortInfo
from modules import BaseModule


class IpmiModule(BaseModule):
    required_tools = ["ipmitool"]

    def match(self, port: PortInfo) -> bool:
        return port.portid == "623" or "rmcp" in port.name

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        tool = config.tool("ipmitool")
        if not tool:
            return []
        return [Job(
            cmd=[
                tool,
                "-I", "lan",
                "-H", host,
                "lan", "print",
            ],
            output_file=f"{host}-{port.portid}.misc.ipmi",
            category="misc",
            host=host,
            description=f"ipmitool lan print {host}:{port.portid}",
        )]
