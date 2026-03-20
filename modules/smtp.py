"""
SMTP module — user enumeration via smtp-user-enum.
Replaces: MSF auxiliary/scanner/smtp/smtp_enum (avoids msfconsole startup overhead).
"""

from __future__ import annotations

from config import Config
from models import Job, PortInfo
from modules import BaseModule


class SmtpModule(BaseModule):
    required_tools = ["smtp-user-enum"]

    def match(self, port: PortInfo) -> bool:
        return port.portid in {"25", "465", "587"} or port.name == "smtp"

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        tool = config.tool("smtp-user-enum")
        if not tool or not config.user_dict.exists():
            return []
        return [Job(
            cmd=[
                tool,
                "-M", "RCPT",
                "-U", str(config.user_dict),
                "-t", host,
                "-p", port.portid,
            ],
            output_file=f"{host}-{port.portid}.misc.smtp",
            category="misc",
            host=host,
            description=f"smtp-user-enum {host}:{port.portid}",
        )]
