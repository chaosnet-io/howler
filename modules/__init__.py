"""
Module system for Howler.
Defines BaseModule ABC and ModuleRegistry for service-to-tool dispatch.
"""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from config import Config
    from models import Job, PortInfo


class BaseModule(ABC):
    """
    Base class for all service scan modules.
    Each module encapsulates the tools used to examine one service/protocol type.
    """

    # Tool binaries this module requires. Checked at startup via shutil.which().
    required_tools: list[str] = []

    def check_tools(self) -> dict[str, bool]:
        """Return {tool_name: is_available} for all required_tools."""
        return {t: shutil.which(t) is not None for t in self.required_tools}

    @abstractmethod
    def match(self, port: "PortInfo") -> bool:
        """Return True if this module should handle the given port."""
        ...

    @abstractmethod
    def jobs(self, host: str, port: "PortInfo", config: "Config") -> list["Job"]:
        """Return Job list for this host/port. May return [] if tools unavailable."""
        ...

    @property
    def name(self) -> str:
        return self.__class__.__name__


class ModuleRegistry:
    """
    Registry of all service modules.
    Unlike the original nightcall if/elif chain, ALL matching modules
    are dispatched — so e.g. ssl_tls and http both fire on HTTPS ports.
    """

    def __init__(self) -> None:
        self._modules: list[BaseModule] = []

    def register(self, module: BaseModule) -> None:
        self._modules.append(module)

    def dispatch(self, host: str, port: "PortInfo", config: "Config") -> list["Job"]:
        """Collect jobs from all modules that match this port."""
        jobs: list["Job"] = []
        for module in self._modules:
            if module.match(port):
                jobs.extend(module.jobs(host, port, config))
        return jobs

    def all_modules(self) -> list[BaseModule]:
        return list(self._modules)


def build_default_registry() -> ModuleRegistry:
    """Instantiate and register all built-in modules."""
    from modules.ssl_tls import SslTlsModule
    from modules.http import HttpModule
    from modules.dns import DnsModule
    from modules.ssh import SshModule
    from modules.smb import SmbModule
    from modules.smtp import SmtpModule
    from modules.snmp import SnmpModule
    from modules.nfs import NfsModule
    from modules.ike import IkeModule
    from modules.ipmi import IpmiModule
    from modules.ftp import FtpModule
    from modules.ldap import LdapModule
    from modules.kerberos import KerberosModule
    from modules.winrm import WinrmModule
    from modules.rdp import RdpModule
    from modules.redis import RedisModule
    from modules.rsync import RsyncModule
    from modules.mssql import MssqlModule
    from modules.mysql import MysqlModule
    from modules.postgres import PostgresModule
    # RMI module removed: nmap NSE rmi-vuln-classloader (already in nse_tcp)
    # covers the same ground without spawning msfconsole per host.

    registry = ModuleRegistry()
    # ssl_tls registered first so testssl.sh runs on HTTPS ports alongside http tools
    registry.register(SslTlsModule())
    registry.register(HttpModule())
    registry.register(DnsModule())
    registry.register(SshModule())
    registry.register(SmbModule())
    registry.register(SmtpModule())
    registry.register(SnmpModule())
    registry.register(NfsModule())
    registry.register(IkeModule())
    registry.register(IpmiModule())
    # Windows / AD coverage
    registry.register(FtpModule())
    registry.register(LdapModule())
    registry.register(KerberosModule())
    registry.register(WinrmModule())
    registry.register(RdpModule())
    # Database / data store coverage
    registry.register(RedisModule())
    registry.register(RsyncModule())
    registry.register(MssqlModule())
    registry.register(MysqlModule())
    registry.register(PostgresModule())
    return registry
