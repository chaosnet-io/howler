"""
SSL/TLS module — runs testssl.sh against ports with TLS enabled.
Replaces: sslscan + MSF openssl_ccs (CCS injection now covered by testssl.sh).
"""

from __future__ import annotations

from config import Config
from models import Job, PortInfo
from modules import BaseModule


class SslTlsModule(BaseModule):
    required_tools = ["testssl.sh"]

    def match(self, port: PortInfo) -> bool:
        return port.ssl

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        tool = config.tool("testssl.sh")
        if not tool:
            return []
        return [Job(
            cmd=[
                tool,
                "--no-color",
                "--quiet",
                "--logfile", f"{host}-{port.portid}.misc.ssl",
                f"{host}:{port.portid}",
            ],
            output_file=f"{host}-{port.portid}.misc.ssl",
            category="misc",
            host=host,
            description=f"testssl.sh {host}:{port.portid}",
        )]
