"""
IPMI module — version, hash dump, cipher zero via MSF modules.
Also checks SMT exposure on port 49152.
"""

from __future__ import annotations

from config import Config
from models import Job, PortInfo
from modules import BaseModule

_IPMI_MODULES = [
    ("auxiliary/scanner/ipmi/ipmi_version",      "ipmi_version"),
    ("auxiliary/scanner/ipmi/ipmi_dumphashes",   "ipmi_dumphashes"),
    ("auxiliary/scanner/ipmi/ipmi_cipher_zero",  "ipmi_cipher_zero"),
]

_SMT_MODULE = ("auxiliary/scanner/http/smt_ipmi_49152_exposure", "smt_ipmi_49152_exposure")


class IpmiModule(BaseModule):
    required_tools = ["msfconsole"]

    def match(self, port: PortInfo) -> bool:
        return (
            port.portid == "623"
            or "rmcp" in port.name
            or port.portid == "49152"
        )

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        msf = config.tool("msfconsole")
        if not msf:
            return []

        jobs: list[Job] = []

        if port.portid == "49152":
            module, ext = _SMT_MODULE
            jobs.append(_msf_job(msf, module, ext, host, port))
        else:
            for module, ext in _IPMI_MODULES:
                jobs.append(_msf_job(msf, module, ext, host, port))

        return jobs


def _msf_job(msf: str, module: str, ext: str, host: str, port: PortInfo) -> Job:
    ssl_val = str(port.ssl).lower()
    return Job(
        cmd=[
            msf, "-q", "-x",
            f"use {module}; set THREADS 6; set RHOSTS {host}; "
            f"set RPORT {port.portid}; set SSL {ssl_val}; run; exit",
            "-o", f"{host}-{port.portid}.msf.{ext}",
        ],
        output_file=f"{host}-{port.portid}.msf.{ext}",
        category="msf",
        host=host,
        description=f"MSF {module} {host}:{port.portid}",
    )
