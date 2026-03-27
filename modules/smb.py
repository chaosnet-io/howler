"""
SMB module — runs enum4linux-ng against SMB ports.
Replaces: enum4linux (Python2, unmaintained).
enum4linux-ng outputs JSON natively with -oA flag.
"""

from __future__ import annotations

from config import Config
from models import Job, PortInfo
from modules import BaseModule


class SmbModule(BaseModule):
    required_tools = ["enum4linux-ng"]

    def match(self, port: PortInfo) -> bool:
        return port.portid in {"139", "445"} and port.protocol == "tcp"

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        tool = config.tool("enum4linux-ng")
        if not tool:
            return []
        return [Job(
            cmd=[tool, "-A", host, "-oA", f"smb-{host}"],
            output_file=f"smb-{host}.misc.enum",
            category="misc",
            host=host,
            description=f"enum4linux-ng {host}",
        )]
