"""
SSH module — runs ssh-audit for algorithm/cipher/key-exchange auditing.
Replaces: MSF auxiliary/scanner/ssh/ssh_enumusers.
ssh-audit covers the broader SSH attack surface (algorithms, host keys, ciphers, MACs).
"""

from __future__ import annotations

from config import Config
from models import Job, PortInfo
from modules import BaseModule


class SshModule(BaseModule):
    required_tools = ["ssh-audit"]

    def match(self, port: PortInfo) -> bool:
        return port.portid == "22" or port.name == "ssh"

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        tool = config.tool("ssh-audit")
        if not tool:
            return []
        return [Job(
            cmd=[tool, "-p", port.portid, host],
            output_file=f"{host}-{port.portid}.misc.ssh_audit",
            category="misc",
            host=host,
            description=f"ssh-audit {host}:{port.portid}",
        )]
