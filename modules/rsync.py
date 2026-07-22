"""
RSync module — enumerate exposed shares via rsync --list-only.

Port 873. Misconfigured rsync daemons expose shares without authentication,
allowing anyone to read (and sometimes write) files. `rsync --list-only`
lists available modules — if any are accessible without auth, that's a
critical finding.
"""

from __future__ import annotations

from config import Config
from models import Job, PortInfo
from modules import BaseModule


class RsyncModule(BaseModule):
    required_tools = ["rsync"]

    def match(self, port: PortInfo) -> bool:
        return port.portid == "873" or port.name == "rsync"

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        tool = config.tool("rsync")
        if not tool:
            return []
        return [Job(
            cmd=[
                tool,
                "--contimeout=10",
                "--list-only",
                f"rsync://{host}:{port.portid}/",
            ],
            output_file=f"{host}-{port.portid}.misc.rsync",
            category="misc",
            host=host,
            description=f"rsync --list-only {host}:{port.portid}",
        )]
