"""
Core data models for Howler.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PortInfo:
    portid: str
    protocol: str       # "tcp" or "udp"
    name: str           # service name e.g. "https", "ssh"
    product: str        # product string e.g. "Apache httpd"
    version: str        # version string
    ssl: bool           # TLS/SSL tunnel detected
    cms: str            # detected CMS e.g. "Wordpress", ""
    state: str = "open"

    @property
    def port_key(self) -> str:
        return f"{self.portid}/{self.protocol}"

    @property
    def is_http(self) -> bool:
        return (
            self.portid in {"80", "443", "8080", "8443", "8000", "8008"}
            or "http" in self.name
            or "http" in self.product
        ) and not any(x in self.product for x in ("httpapi", "rpc"))

    @property
    def scheme(self) -> str:
        return "https" if (self.ssl or self.portid in {"443", "8443"}) else "http"


@dataclass
class HostScan:
    address: str
    ports: dict[str, PortInfo] = field(default_factory=dict)  # key: "portid/proto"
    hostname: Optional[str] = None

    def add_port(self, port: PortInfo) -> None:
        self.ports[port.port_key] = port

    def has_ports(self) -> bool:
        return bool(self.ports)


@dataclass
class Job:
    cmd: list[str]          # argv list — prefer no shell
    output_file: str        # relative output path
    category: str           # "http" | "ssl" | "smb" | "dns" | "misc" | "msf" | "brute"
    host: str               # IP address this job targets
    timeout: Optional[int] = None   # override global timeout if set
    shell: bool = False     # True only for unavoidable shell pipelines
    description: str = ""   # human-readable label for Rich display


@dataclass
class ScanResult:
    job: Job
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False
