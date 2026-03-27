"""
SNMP module — community string brute via MSF snmp_login.
MSF kept here as no widely-available standalone tool matches its convenience for SNMP.
"""

from __future__ import annotations

from config import Config
from models import Job, PortInfo
from modules import BaseModule


class SnmpModule(BaseModule):
    required_tools = ["msfconsole"]

    def match(self, port: PortInfo) -> bool:
        return port.portid == "161" or port.name == "snmp"

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        msf = config.tool("msfconsole")
        if not msf or not config.snmp_dict.exists():
            return []
        module = "auxiliary/scanner/snmp/snmp_login"
        return [Job(
            cmd=[
                msf, "-q", "-x",
                f"use {module}; set THREADS 6; set RHOSTS {host}; "
                f"set RPORT {port.portid}; set VERSION all; set VERBOSE false; "
                f"set PASS_FILE {config.snmp_dict}; run; exit",
                "-o", f"{host}-{port.portid}.msf.snmp_login",
            ],
            output_file=f"{host}-{port.portid}.msf.snmp_login",
            category="msf",
            host=host,
            description=f"MSF snmp_login {host}:{port.portid}",
        )]
