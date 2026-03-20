"""
Java RMI module — MSF java_rmi_server scanner.
No mature standalone alternative to MSF for this protocol.
"""

from __future__ import annotations

from config import Config
from models import Job, PortInfo
from modules import BaseModule


class RmiModule(BaseModule):
    required_tools = ["msfconsole"]

    def match(self, port: PortInfo) -> bool:
        return "rmi" in port.name

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        msf = config.tool("msfconsole")
        if not msf:
            return []
        module = "auxiliary/scanner/misc/java_rmi_server"
        ssl_val = str(port.ssl).lower()
        return [Job(
            cmd=[
                msf, "-q", "-x",
                f"use {module}; set THREADS 6; set RHOSTS {host}; "
                f"set RPORT {port.portid}; set SSL {ssl_val}; run; exit",
                "-o", f"{host}-{port.portid}.msf.java_rmi_server",
            ],
            output_file=f"{host}-{port.portid}.msf.java_rmi_server",
            category="msf",
            host=host,
            description=f"MSF {module} {host}:{port.portid}",
        )]
