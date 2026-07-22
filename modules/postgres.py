"""
PostgreSQL module — connection probe via psql.

Port 5432. Attempts a version query with the default 'postgres' user and no
password. If PostgreSQL allows trust auth (misconfiguration), we get the
version. If auth is required, the error still reveals the server version.

The -w flag suppresses the password prompt so the job doesn't hang in
automation. PGCONNECT_TIMEOUT is set via env to avoid long timeouts on
unreachable hosts — but since the runner doesn't pass env vars, we rely on
psql's default connect timeout plus the job-level timeout.
"""

from __future__ import annotations

from config import Config
from models import Job, PortInfo
from modules import BaseModule


class PostgresModule(BaseModule):
    required_tools = ["psql"]

    def match(self, port: PortInfo) -> bool:
        return port.portid == "5432" or port.name in {"postgresql", "postgres"}

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        tool = config.tool("psql")
        if not tool:
            return []
        return [Job(
            cmd=[
                tool,
                "-h", host,
                "-p", port.portid,
                "-U", "postgres",
                "-w",           # never prompt for password
                "-t",           # tuples only (clean output)
                "-c", "SELECT version();",
            ],
            output_file=f"{host}-{port.portid}.misc.postgres",
            category="misc",
            host=host,
            description=f"psql version probe {host}:{port.portid}",
        )]
