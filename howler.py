#!/usr/bin/env python3

# Howler - Automated Enumeration Scanner
# Modern rewrite of nightcall.py (Lance Pendergrass, Walmart Inc., 2017)
#
# Requires Python 3.10+
# pip install pyyaml rich
#
# System tools (checked at startup, missing tools are skipped with a warning):
#   masscan nmap ffuf gowitness nikto whatweb wafw00f wpscan joomscan
#   testssl.sh enum4linux-ng hydra ssh-audit smtp-user-enum
#   dnsrecon ike-scan showmount msfconsole

import argparse
import asyncio
import ipaddress
import logging
import signal
import subprocess
import sys
import time
from collections import OrderedDict
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler

from config import Config, load_config
from models import HostScan, Job
from modules import ModuleRegistry, build_default_registry
from modules.brute import BruteModule
from runner import AsyncJobRunner
from scanner import portscan, xml_parser
from scanner.discovery import run_discovery
from scanner.portscan import resolve_hostname
from output import organizer, summarizer

VERSION = "2.0.0"

console = Console()


# ── Banner ──────────────────────────────────────────────────────────────────

def banner() -> None:
    wolf = '''\
                                 __
                               .d$$b
                             .' TO$;\\
                            /  : TP._;
                           / _.;  :Tb|
                          /   /   ;j$j
                      _.-"       d$$$$
                    .' ..       d$$$$;
                   /  /P'      d$$$$P. |\\
                  /   "      .d$$$P' |\\^"l
                .'           `T$P^"""""  :
            ._.'      _.'                ;
         `-.-".-'-' ._.       _.-"    .-"
       `.-" _____  ._              .-"
      -(.g$$$$$$$b.              .'
        ""^^T$$$P^)            .(:
          _/  -"  /.'         /:/;
       ._.'-'`-'  ")/         /;/;
    `-.-"..--""   " /         /  ;
   .-" ..--""        -'          :
   ..--""--.-"         (\\      .-(\\
     ..--""              `-\\(\\/;`
       _.                      :
                               ;`-
                              :\\
                              ;
    '''
    console.print(f"\n\t\t.:[ Howler v{VERSION} ]:.  (nightcall reborn)")
    console.print(f"\n\t\t~ Automated Enumeration ~\n\n{wolf}")


# ── Argument parsing ──────────────────────────────────────────────────────

def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="howler",
        description="Automated recon and enumeration scanner",
    )
    parser.add_argument(
        "-sP", "--skip-portscans",
        action="store_true",
        help="skip masscan/nmap, directly import existing XML files from xml/",
    )
    parser.add_argument("-i", "--iface", help="interface for masscan and nmap")
    parser.add_argument("--config", type=Path, help="path to config YAML (default: config.yaml)")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-f", "--target-file", type=Path,
                       help="file containing line-separated IPs/CIDRs")
    group.add_argument("single_address", nargs="?",
                       help="single host or network CIDR")
    group.add_argument("--install-prereqs", action="store_true",
                       help="attempt to install pyyaml and rich via pip")
    group.add_argument("--cleanup", action="store_true",
                       help="re-sort output directory and exit")

    parser.add_argument("-b", "--brute", action="store_true",
                        help="enable credential bruteforcing (mind lockout policies)")
    parser.add_argument("-w", "--web", action="store_true",
                        help="enable extended web scans (ffuf, nikto, CMS scanners)")
    parser.add_argument("--disable-resolve", action="store_true",
                        help="skip hostname resolution pass")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    args = parser.parse_args(argv)

    if not (args.install_prereqs or args.cleanup) and \
            args.target_file is None and args.single_address is None:
        console.print("\n\t[bold red][ No target specified ][/bold red]\n")
        parser.print_help()
        print()
        sys.exit(0)

    return args


# ── Host import ───────────────────────────────────────────────────────────

def import_hosts(
    target_file: Optional[Path],
    single_address: Optional[str],
) -> dict[str, HostScan]:
    hosts: dict[str, HostScan] = {}

    if target_file:
        logging.info(f"Importing targets from: {target_file}")
        lines = target_file.read_text().splitlines()
    else:
        logging.info(f"Single address: {single_address}")
        lines = [single_address]  # type: ignore[list-item]

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if "/" in line:
                target = str(ipaddress.ip_network(line, strict=False))
            else:
                target = str(ipaddress.ip_address(line))
            hosts[target] = HostScan(address=target)
        except ValueError:
            logging.error(f"Invalid IP/CIDR: {line!r}")

    if not hosts:
        console.print("[bold red]No valid IP addresses targeted.[/bold red]")
        sys.exit(1)

    return hosts


def expand_cidrs(hosts: dict[str, HostScan]) -> None:
    """Expand CIDR entries into individual host entries in-place."""
    cidrs = [addr for addr in hosts if "/" in addr]
    for cidr in cidrs:
        del hosts[cidr]
        net = ipaddress.ip_network(cidr, strict=False)
        for ip in net.hosts():
            addr = str(ip)
            if addr not in hosts:
                hosts[addr] = HostScan(address=addr)


def resolve_hostnames(hosts: dict[str, HostScan]) -> None:
    """Reverse-resolve IPs to hostnames and write hostnames.txt."""
    console.print("Resolving hostnames...")
    resolved = 0
    with open("hostnames.txt", "w") as f:
        for addr, scan in hosts.items():
            hostname = resolve_hostname(addr)
            if hostname:
                scan.hostname = hostname
                f.write(f"{addr}\t{hostname}\n")
                resolved += 1
    logging.info(f"Resolved {resolved} hostname(s)")


# ── Tool availability check ───────────────────────────────────────────────

def check_all_tools(registry: ModuleRegistry) -> None:
    """Warn about missing tools at startup so users know what will be skipped."""
    missing: list[str] = []
    seen: set[str] = set()
    for module in registry.all_modules():
        for tool, available in module.check_tools().items():
            if tool not in seen:
                seen.add(tool)
                if not available:
                    missing.append(tool)
    if missing:
        console.print(
            f"[yellow]Warning: {len(missing)} tool(s) not found and will be skipped: "
            f"{', '.join(missing)}[/yellow]"
        )


# ── Signal handling ───────────────────────────────────────────────────────

def signal_term_handler(sig, frame) -> None:
    console.print("\n[bold red]Received SIGTERM — cleaning up and exiting...[/bold red]")
    organizer.final_cleanup()
    sys.exit(1)


# ── Main pipeline ─────────────────────────────────────────────────────────

async def run_pipeline(args: argparse.Namespace, config: Config) -> None:
    registry = build_default_registry()
    check_all_tools(registry)

    runner = AsyncJobRunner(config, console)

    # 1. Import hosts
    hosts = import_hosts(args.target_file, args.single_address)

    all_results = []

    # 2. Host discovery and port scanning
    if not args.skip_portscans:
        live_ips = await run_discovery(
            targets=list(hosts.keys()),
            iface=args.iface,
            config=config,
            console=console,
        )

        if not live_ips:
            console.print("[bold red]No live hosts discovered. Exiting.[/bold red]")
            sys.exit(0)

        # Rebuild hosts dict from discovered IPs only
        hosts = {ip: HostScan(address=ip) for ip in live_ips}

        if not args.disable_resolve:
            resolve_hostnames(hosts)

        # Adaptive port depth: full-port for small target sets
        config.large_test = len(hosts) > config.nmap_large_host_threshold
        full_port = not config.large_test

        nmap_jobs: list[Job] = []
        for host in hosts:
            nmap_jobs.append(portscan.tcp_scan_job(host, args.iface, full_port, config))
            nmap_jobs.append(portscan.udp_scan_job(host, args.iface, config))

        console.print(f"\t[bold][ Initiating host enumeration ({len(nmap_jobs)} jobs) ][/bold]")
        nmap_results = await runner.run_all(nmap_jobs, label="Nmap scanning")
        all_results.extend(nmap_results)
        organizer.post_nmap_cleanup()
    else:
        expand_cidrs(hosts)
        config.large_test = len(hosts) > config.nmap_large_host_threshold
        console.print("Skipping host enumeration — importing existing XML...\n")

    # 3. Import nmap XML
    xml_dir = Path("xml")
    if xml_dir.exists():
        known = set(hosts.keys())
        populated = xml_parser.parse_xml_files(xml_dir, known)
        for addr, scan in populated.items():
            if addr in hosts:
                hosts[addr] = scan
        console.print(f"\t[bold][ Imported data for {len(populated)} host(s) ][/bold]\n")
    else:
        console.print("[yellow]No xml/ directory found — no port data to import[/yellow]")

    # Remove hosts with no port data
    hosts = {addr: scan for addr, scan in hosts.items() if scan.has_ports()}
    logging.debug(f"Hosts with port data: {list(hosts.keys())}")

    # 4. Follow-up scans
    followup_jobs: list[Job] = []
    for host_addr, host_scan in hosts.items():
        for port in host_scan.ports.values():
            followup_jobs.extend(registry.dispatch(host_addr, port, config))

    if followup_jobs:
        console.print(f"\t[bold][ Initiating follow-up scans ({len(followup_jobs)} jobs) ][/bold]")
        followup_results = await runner.run_all(followup_jobs, label="Follow-up scanning")
        all_results.extend(followup_results)

    # 5. Bruteforcing
    if args.brute:
        console.print("\n\t[bold yellow][ Bruteforcing enabled — be mindful of lockout policies ][/bold yellow]")
        brute_module = BruteModule()
        brute_jobs: list[Job] = []
        for host_addr, host_scan in hosts.items():
            for port in host_scan.ports.values():
                brute_jobs.extend(brute_module.jobs(host_addr, port, config))

        if brute_jobs:
            brute_results = await runner.run_all(brute_jobs, label="Bruteforcing")
            all_results.extend(brute_results)

    # 6. Summarize and organize
    summarizer.run(results=all_results, jsonl_output=config.jsonl_output)
    organizer.final_cleanup()

    console.print("\n\t[bold green]~~ Fin ~~[/bold green]\n")


# ── Entry point ───────────────────────────────────────────────────────────

def root_check() -> None:
    result = subprocess.run(["whoami"], capture_output=True, text=True)
    if result.stdout.strip() != "root":
        console.print(" [bold red]~ Must be root to run privileged scans ~[/bold red]\n")
        sys.exit(1)


def install_prereqs() -> None:
    """
    Install pyyaml and rich.
    On Debian/Kali systems, pip install is blocked by PEP 668 (externally-managed-environment).
    Try apt first, fall back to pip with --break-system-packages only if apt is unavailable.
    """
    null = subprocess.DEVNULL

    # Detect Debian/Ubuntu/Kali — use apt if available
    apt = subprocess.run(["which", "apt-get"], capture_output=True).returncode == 0
    if apt:
        console.print("Detected apt — installing via apt-get...")
        pkgs = ["python3-yaml", "python3-rich"]
        result = subprocess.run(
            ["apt-get", "install", "-yqq", *pkgs],
            stdout=null, stderr=null,
        )
        if result.returncode == 0:
            console.print("[green]Prerequisites installed via apt. Relaunch howler.[/green]")
            sys.exit(0)
        console.print("[yellow]apt-get failed, falling back to pip...[/yellow]")

    # Non-Debian systems or apt failure — standard pip
    result = subprocess.run(["pip3", "install", "pyyaml", "rich"], stdout=null, stderr=null)
    if result.returncode == 0:
        console.print("[green]Prerequisites installed via pip. Relaunch howler.[/green]")
        sys.exit(0)

    # PEP 668 managed environment — offer the override flag
    result = subprocess.run(
        ["pip3", "install", "--break-system-packages", "pyyaml", "rich"],
        stdout=null, stderr=null,
    )
    if result.returncode == 0:
        console.print("[green]Prerequisites installed. Relaunch howler.[/green]")
        sys.exit(0)

    console.print(
        "[red]Automatic install failed.[/red]\n"
        "On Kali/Debian, run:  apt-get install python3-yaml python3-rich\n"
        "Otherwise:            pip3 install pyyaml rich"
    )
    sys.exit(1)


def init_logging(config: Config) -> None:
    level = getattr(logging, config.log_level.upper(), logging.INFO)
    log_filename = f"Howler_{time.strftime('%Y-%b-%d_%H-%M-%S')}.log"
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%b-%d %H:%M:%S",
        handlers=[
            logging.FileHandler(log_filename),
            RichHandler(console=console, show_time=False, show_path=False,
                        level=logging.WARNING),  # only warnings+ to console
        ],
    )
    logging.info(f"Howler v{VERSION} started")


if __name__ == "__main__":
    banner()
    root_check()
    signal.signal(signal.SIGTERM, signal_term_handler)

    args = parse_args(sys.argv[1:])

    config = load_config(args.config if hasattr(args, "config") else None)
    config.enable_brute = args.brute
    config.enable_web = args.web

    init_logging(config)
    logging.debug(f"Arguments: {args}")

    if args.install_prereqs:
        install_prereqs()

    if args.cleanup:
        console.print("Cleanup requested...")
        organizer.post_nmap_cleanup()
        organizer.final_cleanup()
        sys.exit(0)

    subprocess.run(["msfdb", "start"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        asyncio.run(run_pipeline(args, config))
    except KeyboardInterrupt:
        console.print("\n[bold red]Keyboard interrupt — cleaning up...[/bold red]")
        organizer.final_cleanup()
        sys.exit(1)
