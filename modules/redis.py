"""
Redis module — unauthenticated instance probe via redis-cli INFO.

Port 6379. On misconfigured (unauthenticated) Redis instances, `redis-cli INFO`
returns the server version, OS, connected clients, memory usage, and config.
This is one of the most critical misconfigurations to catch — open Redis
instances are routinely exploited for ransomware, cryptomining, and SSH key
injection.

If Redis requires auth, the command fails with NOAUTH — still useful to
confirm the service is there, but the real finding is the unauth case.
"""

from __future__ import annotations

from config import Config
from models import Job, PortInfo
from modules import BaseModule


class RedisModule(BaseModule):
    required_tools = ["redis-cli"]

    def match(self, port: PortInfo) -> bool:
        return port.portid == "6379" or port.name == "redis"

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        tool = config.tool("redis-cli")
        if not tool:
            return []
        return [Job(
            cmd=[
                tool,
                "-h", host,
                "-p", port.portid,
                "--connect-timeout", "10",
                "INFO",
            ],
            output_file=f"{host}-{port.portid}.misc.redis",
            category="misc",
            host=host,
            description=f"redis-cli INFO {host}:{port.portid}",
        )]
