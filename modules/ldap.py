"""
LDAP module — anonymous bind user/group enumeration via windapsearch.

Targets AD domain controllers on LDAP (389), LDAPS (636), Global Catalog
(3268), and Global Catalog SSL (3269). windapsearch handles the rootDSE
lookup + naming context discovery internally, so we just point it at the
host with an empty domain (anonymous bind).

Like the SMB module, jobs don't include the port in the description or
output file: windapsearch connects to the host, not a specific port, so
running it against 389 vs 636 vs 3268 produces identical output. Safe
duplicates — on resume, if any one completed, all skip together.
"""

from __future__ import annotations

import netutil
from config import Config
from models import Job, PortInfo
from modules import BaseModule


class LdapModule(BaseModule):
    required_tools = ["windapsearch"]

    def match(self, port: PortInfo) -> bool:
        return (
            port.portid in {"389", "636", "3268", "3269"}
            or "ldap" in port.name
        )

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        tool = config.tool("windapsearch")
        if not tool:
            return []
        return [
            Job(
                cmd=[tool, "-d", "", "--dc-ip", host, "-U"],
                output_file=f"{netutil.safe_filename(host)}.misc.ldap_users",
                category="misc",
                host=host,
                description=f"windapsearch users {host}",
            ),
            Job(
                cmd=[tool, "-d", "", "--dc-ip", host, "-G"],
                output_file=f"{netutil.safe_filename(host)}.misc.ldap_groups",
                category="misc",
                host=host,
                description=f"windapsearch groups {host}",
            ),
        ]
