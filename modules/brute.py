"""
Brute-force module — flag-gated (requires --brute CLI flag).
Replaces medusa with hydra (more actively maintained, broader protocol support).
MSF tftpbrute kept for TFTP as no standalone alternative.
"""

from __future__ import annotations

from config import Config
from models import Job, PortInfo
from modules import BaseModule

_HYDRA_PROTOCOLS = {"ftp", "mssql", "mysql", "rexec", "rlogin", "rsh", "smtp", "ssh", "telnet", "vnc"}


class BruteModule(BaseModule):
    required_tools = ["hydra"]

    def match(self, port: PortInfo) -> bool:
        if not self._config_brute_enabled:
            return False
        return (
            port.name in _HYDRA_PROTOCOLS
            or port.portid == "69"
            or "tftp" in port.name
        )

    # Brute module gets config.enable_brute checked at dispatch time by the runner,
    # but we also need it in match(). The registry dispatch passes config, but match()
    # only receives port. We handle this via jobs() returning [] when brute disabled.
    _config_brute_enabled: bool = True

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        if not config.enable_brute:
            return []

        # TFTP via MSF
        if port.portid == "69" or "tftp" in port.name:
            return _tftp_brute(host, port, config)

        # Auth protocols via hydra
        if port.name in _HYDRA_PROTOCOLS:
            return _hydra_brute(host, port, config)

        return []


def _hydra_brute(host: str, port: PortInfo, config: Config) -> list[Job]:
    tool = config.tool("hydra")
    if not tool:
        return []
    if not config.user_dict.exists() or not config.pass_dict.exists():
        return []

    ssl_flag = ["-S"] if port.ssl else []
    return [Job(
        cmd=[
            tool,
            "-L", str(config.user_dict),
            "-P", str(config.pass_dict),
            "-e", "ns",
            "-t", "8",
            "-s", port.portid,
            *ssl_flag,
            host,
            port.name,
        ],
        output_file=f"{host}.{port.name}.brute",
        category="brute",
        host=host,
        description=f"hydra {port.name} {host}:{port.portid}",
    )]


def _tftp_brute(host: str, port: PortInfo, config: Config) -> list[Job]:
    msf = config.tool("msfconsole")
    if not msf:
        return []
    module = "auxiliary/scanner/tftp/tftpbrute"
    return [Job(
        cmd=[
            msf, "-q", "-x",
            f"use {module}; set THREADS 6; set RHOSTS {host}; "
            f"set RPORT {port.portid}; run; exit",
            "-o", f"{host}-{port.portid}.msf.tftpbrute",
        ],
        output_file=f"{host}-{port.portid}.msf.tftpbrute",
        category="brute",
        host=host,
        description=f"MSF tftpbrute {host}:{port.portid}",
    )]
