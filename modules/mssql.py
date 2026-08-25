"""
MSSQL module — connection probe via impacket-mssqlclient.

Port 1433. Currently only hydra-bruted. This module tries a null session
connection — if MSSQL allows it (misconfiguration), we get version info and
interactive access. If not, the error confirms the service and its version.

Separate from brute (--brute flag) because the null probe is always safe
(no lockout risk) and catches a different class of misconfiguration.
"""

from __future__ import annotations

import netutil
from config import Config
from models import Job, PortInfo
from modules import BaseModule


class MssqlModule(BaseModule):
    required_tools = ["impacket-mssqlclient"]

    def match(self, port: PortInfo) -> bool:
        return port.portid == "1433" or port.name in {"mssql", "ms-sql-s"}

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        tool = config.tool("impacket-mssqlclient")
        if not tool:
            return []
        return [Job(
            cmd=[
                tool,
                "-no-pass",
                "-port", port.portid,
                f"''@{netutil.bracket(host)}",
            ],
            output_file=f"{netutil.safe_filename(host)}-{port.portid}.misc.mssql",
            category="misc",
            host=host,
            description=f"impacket-mssqlclient null probe {host}:{port.portid}",
        )]
