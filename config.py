"""
Configuration loader for Howler.
Loads config.yaml and merges with hardcoded defaults.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


@dataclass
class Config:
    # Concurrency
    concurrent_tasks: int = 4
    task_timeout: int = 3600
    discovery_wait: int = 60

    # Masscan
    masscan_rate: int = 2000
    masscan_retries: int = 2
    masscan_ports: str = (
        "21,22,23,25,26,53,80,81,110-111,113,135,139,143,179,199,443,445,465,"
        "514-515,548,554,587,646,993,995,1025,1026,1027,1033,1035,1443,1720,1723,"
        "1884,1885,1886,1981,1982,1983,1987,1988,1989,1996,2000,2001,2002,2065,"
        "2067,2115,3306,3389,4000,4001,4002,5060,5061,5666,5900,6000,6001,6002,"
        "7767,7768,8000,8008,8080,8443,8888,9000,9001,9002,10000,21002,21010,"
        "32768,49152,49154,49338,51003,51004,54138,"
        "U:53,U:69,U:111,U:123,U:135,U:137,U:161,U:500,U:514,U:520,U:623,"
        "U:1033,U:1434,U:2049,U:4500,U:5353"
    )

    # Nmap
    nmap_large_host_threshold: int = 100
    nmap_version_intensity: int = 5
    nmap_max_retries: int = 2
    nmap_max_rtt_timeout: str = "300ms"
    nmap_max_scan_delay: str = "300ms"
    nmap_nse_tcp: str = (
        "ajp-headers,amqp-info,banner,cassandra-info,dns-zone-transfer,"
        "ftp-anon,ftp-syst,http-apache-server-status,http-backup-finder,"
        "http-config-backup,http-devframework,http-method-tamper,http-methods,"
        "http-open-proxy,http-passwd,http-robots.txt,http-shellshock,"
        "http-sitemap-generator,http-title,http-vuln-cve2017-5638,"
        "http-vuln-cve2017-5689,http-webdav-scan,imap-capabilities,iscsi-info,"
        "jdwp-info,ldap-rootdse,ldap-search,mongodb-databases,mongodb-info,"
        "mqtt-subscribe,ms-sql-info,mysql-empty-password,mysql-info,"
        "nfs-showmount,pop3-capabilities,redis-info,rmi-vuln-classloader,"
        "rsync-list-modules,sip-methods,smb-enum-domains,smb-enum-shares,"
        "smb-enum-users,smb-os-discovery,smb-vuln-ms17-010,smtp-commands,"
        "ssl-heartbleed,ssl-known-key,supermicro-ipmi-conf,tls-ticketbleed,"
        "unusual-port,x11-access"
    )
    nmap_nse_udp: str = (
        "banner,dns-nsid,dns-recursion,dns-service-discovery,ipmi-cipher-zero,"
        "ipmi-version,ms-sql-info,nbstat,nfs-showmount,ntp-info,sip-methods,"
        "smb-enum-domains,smb-enum-shares,smb-enum-users,smb-os-discovery,"
        "snmp-sysdescr,snmp-win32-shares,snmp-win32-software,snmp-win32-users,"
        "unusual-port,upnp-info"
    )
    nmap_udp_ports: str = (
        "53,67-69,80,88,111,123,135,137-139,161,389,445,500,514,520,623,"
        "1033,1433,1434,1900,2049,4500,5060,5353,49152"
    )

    # Wordlists
    user_dict: Path = field(default_factory=lambda: Path("/usr/share/ncrack/minimal.usr"))
    pass_dict: Path = field(default_factory=lambda: Path("/usr/share/seclists/Passwords/unix_passwords.txt"))
    snmp_dict: Path = field(default_factory=lambda: Path("/usr/share/seclists/Miscellaneous/default-snmp-strings.txt"))
    http_fuzz_small: Path = field(default_factory=lambda: Path("/usr/share/seclists/Discovery/Web-Content/common.txt"))
    http_fuzz_large: Path = field(default_factory=lambda: Path("/usr/share/seclists/Discovery/Web-Content/big.txt"))

    # Tool path overrides (None = auto-detect via shutil.which)
    tool_paths: dict[str, Optional[str]] = field(default_factory=dict)

    # Feature flags (set by CLI args, may also come from config)
    randomize_jobs: bool = False
    enable_brute: bool = False
    enable_web: bool = False
    jsonl_output: bool = True

    # Runtime state (set during pipeline, not from config)
    large_test: bool = False

    # Logging
    log_level: str = "INFO"

    def tool(self, name: str) -> Optional[str]:
        """Return resolved path for a tool, or None if not found."""
        override = self.tool_paths.get(name)
        if override:
            return override
        return shutil.which(name)

    def tool_available(self, name: str) -> bool:
        return self.tool(name) is not None


def load_config(path: Optional[Path] = None) -> Config:
    """Load config from YAML file, merging over defaults."""
    config = Config()

    if not _YAML_AVAILABLE:
        return config

    # Try explicit path, then local config.yaml, then script-adjacent config.yaml
    candidates = []
    if path:
        candidates.append(path)
    candidates.append(Path("config.yaml"))
    candidates.append(Path(__file__).parent / "config.yaml")

    data: dict[str, Any] = {}
    for candidate in candidates:
        if candidate.exists():
            with open(candidate) as f:
                data = yaml.safe_load(f) or {}
            break

    if not data:
        return config

    # Apply YAML values to config
    conc = data.get("concurrency", {})
    config.concurrent_tasks = conc.get("concurrent_tasks", config.concurrent_tasks)
    config.task_timeout = conc.get("task_timeout", config.task_timeout)
    config.discovery_wait = conc.get("discovery_wait", config.discovery_wait)

    mass = data.get("masscan", {})
    config.masscan_rate = mass.get("rate", config.masscan_rate)
    config.masscan_retries = mass.get("retries", config.masscan_retries)
    if "ports" in mass:
        config.masscan_ports = mass["ports"]

    nmap = data.get("nmap", {})
    config.nmap_large_host_threshold = nmap.get("large_host_threshold", config.nmap_large_host_threshold)
    config.nmap_version_intensity = nmap.get("version_intensity", config.nmap_version_intensity)
    config.nmap_max_retries = nmap.get("max_retries", config.nmap_max_retries)
    config.nmap_max_rtt_timeout = nmap.get("max_rtt_timeout", config.nmap_max_rtt_timeout)
    config.nmap_max_scan_delay = nmap.get("max_scan_delay", config.nmap_max_scan_delay)
    if "nse_tcp" in nmap:
        config.nmap_nse_tcp = nmap["nse_tcp"]
    if "nse_udp" in nmap:
        config.nmap_nse_udp = nmap["nse_udp"]
    if "udp_ports" in nmap:
        config.nmap_udp_ports = nmap["udp_ports"]

    wl = data.get("wordlists", {})
    if "user_dict" in wl:
        config.user_dict = Path(wl["user_dict"])
    if "pass_dict" in wl:
        config.pass_dict = Path(wl["pass_dict"])
    if "snmp_dict" in wl:
        config.snmp_dict = Path(wl["snmp_dict"])
    if "http_fuzz_small" in wl:
        config.http_fuzz_small = Path(wl["http_fuzz_small"])
    if "http_fuzz_large" in wl:
        config.http_fuzz_large = Path(wl["http_fuzz_large"])

    tools = data.get("tools", {})
    for tool_name, tool_path in tools.items():
        if tool_path is not None:
            config.tool_paths[tool_name] = tool_path

    feat = data.get("features", {})
    config.randomize_jobs = feat.get("randomize_jobs", config.randomize_jobs)
    config.jsonl_output = feat.get("jsonl_output", config.jsonl_output)

    out = data.get("output", {})
    config.log_level = out.get("log_level", config.log_level)

    return config
