"""
Kerberos module — user enumeration + ASREPRoasting.

Tools:
  - kerbrute: user enumeration via AS-REQ (doesn't trigger lockouts)
  - impacket-GetNPUsers: ASREPRoasting (extracts TGTs for accounts with
    'DONT_REQ_PREAUTH')

Both need a domain name. We derive it from the PTR record (reusing the
dns module's resolver). If the domain can't be resolved, the module skips
with a warning — the user can re-run with a domain manually.

Natural companion to LDAP: LDAP finds the users, Kerberos validates them
and finds ASREPRoastable accounts.
"""

from __future__ import annotations

import logging
from typing import Optional

import netutil
from config import Config
from models import Job, PortInfo
from modules import BaseModule
from modules.dns import _resolve_domain

log = logging.getLogger(__name__)


class KerberosModule(BaseModule):
    required_tools = ["kerbrute", "impacket-GetNPUsers"]

    def match(self, port: PortInfo) -> bool:
        return port.portid == "88" or port.name == "kerberos"

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        domain = _resolve_domain(host, tcp=False)
        if not domain:
            log.warning(
                f"Could not derive AD domain for Kerberos on {host} — "
                f"skipping kerbrute/GetNPUsers. Run manually with a known domain."
            )
            return []

        jobs: list[Job] = []

        kerbrute = config.tool("kerbrute")
        if kerbrute and config.user_dict.exists():
            jobs.append(Job(
                cmd=[
                    kerbrute, "userenum",
                    "--dc", host,
                    "-d", domain,
                    str(config.user_dict),
                ],
                output_file=f"{netutil.safe_filename(host)}-{port.portid}.misc.kerbrute",
                category="misc",
                host=host,
                description=f"kerbrute userenum {host} ({domain})",
            ))

        getnpusers = config.tool("impacket-GetNPUsers")
        if getnpusers and config.user_dict.exists():
            jobs.append(Job(
                cmd=[
                    getnpusers,
                    "-dc-ip", host,
                    "-usersfile", str(config.user_dict),
                    f"{domain}/",
                ],
                output_file=f"{netutil.safe_filename(host)}-{port.portid}.misc.asreproast",
                category="misc",
                host=host,
                description=f"GetNPUsers {host} ({domain})",
            ))

        return jobs
