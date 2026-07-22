"""
WinRM module — banner/auth check via curl.

WinRM runs on 5985 (HTTP) and 5986 (HTTPS). A simple header grab
confirms the service and reveals the server version (typically
Microsoft-HTTPAPI/2.0). No authentication attempted — just a banner
check to confirm WinRM is exposed.
"""

from __future__ import annotations

from config import Config
from models import Job, PortInfo
from modules import BaseModule


class WinrmModule(BaseModule):
    required_tools = ["curl"]

    def match(self, port: PortInfo) -> bool:
        return port.portid in {"5985", "5986"} or port.name == "wsman"

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        tool = config.tool("curl")
        if not tool:
            return []
        scheme = "https" if port.portid == "5986" else "http"
        return [Job(
            cmd=[
                tool,
                "-s", "-k", "-I",
                "--connect-timeout", "10",
                f"{scheme}://{host}:{port.portid}/wsman",
            ],
            output_file=f"{host}-{port.portid}.misc.winrm",
            category="misc",
            host=host,
            description=f"curl WinRM banner {host}:{port.portid}",
        )]
