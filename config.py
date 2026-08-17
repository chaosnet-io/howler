"""
Configuration loader for Howler.
Loads config.yaml and merges with hardcoded defaults.
"""

from __future__ import annotations

import functools
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@functools.lru_cache(maxsize=1)
def _detect_seclists_roots() -> tuple[Path, ...]:
    """
    Locate installed SecLists trees across distros/package managers.

    Distros disagree on where SecLists lands: Kali uses /usr/share/seclists,
    Nixpkgs installs to <prefix>/share/wordlists/seclists, etc. Under sudo the
    real profile is the invoking user's (SUDO_USER), not root's — so we probe
    those too. Cheap: one stat per candidate, memoised for the whole run.
    """
    candidates: list[str] = []

    # Explicit override wins.
    for var in ("HOWLER_SECLISTS", "SECLISTS_ROOT"):
        if os.environ.get(var):
            candidates.append(os.environ[var])

    candidates += [
        "/usr/share/seclists",
        "/usr/share/wordlists/seclists",          # Kali symlink / Nix convention
        "/run/current-system/sw/share/wordlists/seclists",   # NixOS systemPackages
        "/run/current-system/sw/share/seclists",
        "~/.nix-profile/share/wordlists/seclists",           # Nix user profile
        "~/.nix-profile/share/seclists",
        "/opt/seclists",
        "/opt/SecLists",
        "/usr/local/share/seclists",
        "/opt/homebrew/share/seclists",           # macOS
    ]

    # Under sudo, HOME/~ point at root; the wordlists usually belong to SUDO_USER.
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        candidates += [
            f"/home/{sudo_user}/.nix-profile/share/wordlists/seclists",
            f"/home/{sudo_user}/.nix-profile/share/seclists",
            f"/etc/profiles/per-user/{sudo_user}/share/wordlists/seclists",
            f"/etc/profiles/per-user/{sudo_user}/share/seclists",
        ]

    roots: list[Path] = []
    seen: set[Path] = set()
    for raw in candidates:
        p = Path(raw).expanduser()
        if p not in seen and p.is_dir():
            seen.add(p)
            roots.append(p)
    return tuple(roots)

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


# ── External profile tuning ──────────────────────────────────────────────────
# Values the --external flag layers over the internal-LAN defaults. Kept as
# module constants (not config keys) because --external is a code-level profile,
# not a data-driven one — see Config.apply_external_profile().

# masscan packets/sec cap for internet-facing targets. 2000 pps (the internal
# default) trips IDS/IPS and upstream rate-limits, and can get the source
# address null-routed. Lower is stealthier and a better netizen.
EXTERNAL_MASSCAN_RATE = 300

# nmap --max-rtt-timeout for internet latency. 300ms suits a LAN but silently
# drops ports on higher-latency paths (false negatives).
EXTERNAL_MAX_RTT_TIMEOUT = "1250ms"

# NSE scripts dropped in external mode. Policy: this is an authorised pentest
# tool, so intrusive vuln/exploit checks and the http-put file-write are KEPT;
# only scripts with a documented denial-of-service / target-crash risk are
# removed. smb-vuln-ms17-010 can crash the target host (see nmap script docs).
EXTERNAL_DOS_SCRIPTS = frozenset({"smb-vuln-ms17-010"})

# Curated external attack-surface port set. External scanning wants the ports
# realistically exposed to the internet — plus the internal-only services (SMB,
# RDP, databases, IPMI, X11) that are CRITICAL findings *if* exposed — not the
# LAN chatter (mDNS, LLMNR, NetBIOS broadcast, vendor-appliance high ports) that
# pads the internal default. Applied by apply_external_profile() to both masscan
# (discovery) and nmap (enumeration), so external scans stay fast and focused
# instead of doing a full -p- sweep at internet latency.
EXTERNAL_TCP_PORTS = (
    "21,22,23,25,53,80,81,88,110,111,135,139,143,389,443,445,465,587,636,873,"
    "990,993,995,1080,1194,1433,1521,1723,2049,2082,2083,2375,2376,3000,3268,"
    "3269,3306,3389,4443,5000,5432,5601,5900,5984,5985,5986,6000,6001,6379,6443,"
    "7001,8000,8008,8009,8080,8081,8086,8443,8888,9000,9092,9200,9300,9443,"
    "10000,11211,27017"
)
EXTERNAL_UDP_PORTS = "53,69,111,123,137,161,500,623,1434,1900,4500,5060"
EXTERNAL_MASSCAN_PORTS = EXTERNAL_TCP_PORTS + "," + ",".join(
    f"U:{p}" for p in EXTERNAL_UDP_PORTS.split(",")
)


def _filter_nse(script_csv: str, drop: "frozenset[str]") -> str:
    """Return a comma-separated NSE list with ``drop`` names removed."""
    kept = [s.strip() for s in script_csv.split(",") if s.strip() and s.strip() not in drop]
    return ",".join(kept)


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
        "21,22,23,25,26,53,80,81,88,110-111,113,135,139,143,179,199,389,443,445,465,"
        "514-515,548,554,587,636,646,873,993,995,1025,1026,1027,1033,1035,1433,1443,"
        "1720,1723,1884,1885,1886,1981,1982,1983,1987,1988,1989,1996,2000,2001,2002,"
        "2065,2067,2115,3268,3269,3306,3389,4000,4001,4002,5060,5061,5432,5666,5900,"
        "5985,5986,6000,6001,6002,6379,7767,7768,8000,8008,8080,8443,8888,9000,9001,"
        "9002,10000,21002,21010,32768,49152,49154,49338,51003,51004,54138,"
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
    # When set (external profile), nmap scans exactly this TCP port set instead
    # of the full-port / top-1000 heuristic. None = internal adaptive behaviour.
    nmap_tcp_ports: Optional[str] = None
    # --script-args passed to the nmap TCP scan. Sourced from config.yaml's
    # nmap.nse_args block (previously hardcoded in scanner/portscan.py).
    nse_args: dict[str, Any] = field(default_factory=lambda: {
        "http_put_url": "/",
        "http_put_file": "/etc/timezone",
        "cmd": "whoami",
        "httpspider_maxpagecount": 100,
    })

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
    enable_external: bool = False
    jsonl_output: bool = True

    # Scan-shape toggles. Default to the internal-LAN profile; the external
    # profile (apply_external_profile) turns these off.
    os_detect: bool = True   # nmap -O
    scan_udp: bool = True    # generate nmap UDP deep-enum jobs

    # Scope control: file of out-of-scope IPs/CIDRs excluded from masscan
    # (--excludefile) and nmap (--excludefile). None = no exclusions.
    exclude_file: Optional[str] = None

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

    def resolve_wordlist(self, configured: "str | Path") -> Optional[Path]:
        """
        Resolve a wordlist path, falling back to auto-detected SecLists roots.

        If the configured path exists, use it verbatim. Otherwise, if it points
        inside a SecLists tree (…/seclists/<suffix>), re-root <suffix> against
        each detected install so the default config works without edits on any
        distro. Returns None if nothing matches (caller should skip + warn).
        """
        p = Path(configured).expanduser()
        if p.is_file():
            return p

        parts = p.parts
        for i in range(len(parts) - 1, -1, -1):
            if parts[i].lower() == "seclists":
                suffix = Path(*parts[i + 1:])
                for root in _detect_seclists_roots():
                    candidate = root / suffix
                    if candidate.is_file():
                        return candidate
                break
        return None

    def nse_script_args(self) -> str:
        """Build the nmap ``--script-args`` string from ``self.nse_args``.

        Was hardcoded in scanner/portscan.py; now sourced from config so the
        http-put file-write target, command, and spider depth are tunable.
        Only keys that are set contribute, so blanking one in config.yaml
        drops the corresponding script arg.
        """
        a = self.nse_args
        parts: list[str] = []
        if a.get("http_put_url"):
            parts.append(f'http-put.url="{a["http_put_url"]}"')
        if a.get("http_put_file"):
            parts.append(f'http-put.file="{a["http_put_file"]}"')
        if a.get("cmd"):
            parts.append(f'cmd="{a["cmd"]}"')
        if a.get("httpspider_maxpagecount") is not None:
            parts.append(f'httpspider.maxpagecount={a["httpspider_maxpagecount"]}')
        return ",".join(parts)

    def apply_external_profile(self) -> None:
        """Retune the internal-LAN defaults for internet-facing targets.

        Applied when ``--external`` is given. Relative to the internal profile:

          * masscan rate is capped low — 2000 pps trips IDS/IPS and upstream
            rate-limits over the internet and risks the source being
            null-routed. (``min`` so a lower rate already set in config wins.)
          * ``--max-rtt-timeout`` is relaxed for internet latency: 300ms drops
            ports on higher-latency paths (false negatives).
          * OS detection (``-O``) is disabled — unreliable through firewalls,
            slow, and noisy.
          * Deep UDP enumeration is skipped (the pipeline honours ``scan_udp``):
            UDP scanning across the internet is slow and lossy.
          * DoS / crash-risk NSE scripts are dropped. Intrusive vuln/exploit
            scripts and the http-put file-write are KEPT — this is an
            authorised penetration-testing tool.
        """
        self.masscan_rate = min(self.masscan_rate, EXTERNAL_MASSCAN_RATE)
        self.nmap_max_rtt_timeout = EXTERNAL_MAX_RTT_TIMEOUT
        self.os_detect = False
        self.scan_udp = False
        self.nmap_nse_tcp = _filter_nse(self.nmap_nse_tcp, EXTERNAL_DOS_SCRIPTS)
        self.nmap_nse_udp = _filter_nse(self.nmap_nse_udp, EXTERNAL_DOS_SCRIPTS)
        # Focus discovery + enumeration on the external attack surface. Only swap
        # masscan's port list if it's still the untouched internal default — an
        # explicit masscan.ports in config.yaml wins (mirrors the rate min() rule).
        # nmap always uses the curated TCP set in external mode.
        if self.masscan_ports == Config.__dataclass_fields__["masscan_ports"].default:
            self.masscan_ports = EXTERNAL_MASSCAN_PORTS
        self.nmap_tcp_ports = EXTERNAL_TCP_PORTS


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
    if "nse_args" in nmap and isinstance(nmap["nse_args"], dict):
        # Merge over defaults so a partial nse_args block keeps the rest.
        config.nse_args = {**config.nse_args, **nmap["nse_args"]}

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
