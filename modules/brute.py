"""
Brute-force module — flag-gated (requires --brute CLI flag).
Replaces medusa with hydra (more actively maintained, broader protocol support).
TFTP brute previously used MSF tftpbrute; replaced with nmap NSE tftp-enum
(invokes nmap standalone, no msfconsole dependency).
"""

from __future__ import annotations

import netutil
from config import Config
from models import Job, PortInfo
from modules import BaseModule

_HYDRA_PROTOCOLS = {"ftp", "mssql", "mysql", "rexec", "rlogin", "rsh", "smtp", "ssh", "telnet", "vnc"}


class BruteModule(BaseModule):
    required_tools = ["hydra", "nmap"]

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

        # TFTP via nmap NSE tftp-enum
        if port.portid == "69" or "tftp" in port.name:
            return _tftp_enum(host, port, config)

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
        output_file=f"{netutil.safe_filename(host)}.{port.name}.brute",
        category="brute",
        host=host,
        description=f"hydra {port.name} {host}:{port.portid}",
    )]


def _tftp_enum(host: str, port: PortInfo, config: Config) -> list[Job]:
    """TFTP enumeration via nmap NSE tftp-enum.

    Uses nmap directly (no msfconsole). tftp-enum reads a default filelist
    shipped with nmap; can be overridden via ``tftp-enum.filelist=<path>`` in
    nse_args, but we keep defaults to avoid wordlist plumbing.
    """
    nmap = config.tool("nmap")
    if not nmap:
        return []
    return [Job(
        cmd=[
            nmap,
            "-sU", "-p", "69",
            "--script", "tftp-enum",
            "-n", "-Pn",
            *(["-6"] if netutil.is_ipv6(host) else []),
            host,
        ],
        output_file=f"{netutil.safe_filename(host)}-{port.portid}.misc.tftp_enum",
        category="misc",
        host=host,
        description=f"nmap tftp-enum {host}:{port.portid}",
    )]

