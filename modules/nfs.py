"""
NFS module — enumerates NFS exports via showmount.
"""

from __future__ import annotations

from config import Config
from models import Job, PortInfo
from modules import BaseModule


class NfsModule(BaseModule):
    required_tools = ["showmount"]

    def match(self, port: PortInfo) -> bool:
        return port.portid == "2049" or port.name == "nfs"

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        tool = config.tool("showmount")
        if not tool:
            return []
        return [Job(
            cmd=[tool, "-e", host],
            output_file=f"{host}.misc.nfs",
            category="misc",
            host=host,
            description=f"showmount -e {host}",
        )]
