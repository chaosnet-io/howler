"""
MySQL module — connection probe via mysql client.

Port 3306. Currently only hydra-bruted. This module attempts a version query
— if MySQL allows unauthenticated access (rare but not unheard of, especially
on embedded devices), we get the version. If auth is required, the error
message still contains the server version banner.

Separate from brute (--brute flag) because the probe is always safe (no
lockout risk) and catches misconfigurations hydra wouldn't.
"""

from __future__ import annotations

from config import Config
from models import Job, PortInfo
from modules import BaseModule


class MysqlModule(BaseModule):
    required_tools = ["mysql"]

    def match(self, port: PortInfo) -> bool:
        return port.portid == "3306" or port.name == "mysql"

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        tool = config.tool("mysql")
        if not tool:
            return []
        return [Job(
            cmd=[
                tool,
                "-h", host,
                "-P", port.portid,
                "--connect-timeout=10",
                "-N", "-B",
                "-e", "SELECT VERSION();",
            ],
            output_file=f"{host}-{port.portid}.misc.mysql",
            category="misc",
            host=host,
            description=f"mysql version probe {host}:{port.portid}",
        )]
