"""
FTP module — anonymous login check + banner/syst info via nmap NSE.

Port 21 is currently only bruted (hydra in --brute mode). This module
fires automatically (no flag gating) and checks for anonymous FTP access
— one of the most common trivial findings. Uses nmap's ftp-anon and
ftp-syst NSE scripts standalone (same pattern as TFTP brute's tftp-enum).

Note: ftp-anon and ftp-syst are already in nse_tcp, so they run during
the main nmap scan. This standalone module ensures the check still runs
when portscans are skipped (-sP) and gives a dedicated output file.
"""

from __future__ import annotations

import netutil
from config import Config
from models import Job, PortInfo
from modules import BaseModule


class FtpModule(BaseModule):
    required_tools = ["nmap"]

    def match(self, port: PortInfo) -> bool:
        return port.portid == "21" or port.name == "ftp"

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        nmap = config.tool("nmap")
        if not nmap:
            return []
        return [Job(
            cmd=[
                nmap,
                "-p", "21",
                "--script", "ftp-anon,ftp-syst",
                "-n", "-Pn",
                *(["-6"] if netutil.is_ipv6(host) else []),
                host,
            ],
            output_file=f"{netutil.safe_filename(host)}-{port.portid}.misc.ftp",
            category="misc",
            host=host,
            description=f"nmap ftp-anon,ftp-syst {host}:{port.portid}",
        )]
