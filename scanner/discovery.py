"""
Host discovery via masscan.
Runs masscan, converts output, returns list of live IP strings.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import subprocess
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from config import Config

log = logging.getLogger(__name__)


async def run_discovery(
    targets: list[str],
    iface: Optional[str],
    config: Config,
    console: Console,
) -> list[str]:
    """
    Run masscan against targets, wait for completion, return live IP list.
    Returns empty list if masscan is not available or no hosts found.
    """
    masscan_bin = config.tool("masscan")
    if not masscan_bin:
        console.print("[bold red]masscan not found — skipping host discovery[/bold red]")
        return []

    host_count = _count_hosts(targets)
    est_duration = _estimate_scan_duration(config, host_count)

    log.info(f"Starting masscan against {host_count} addresses, estimated {est_duration:.1f}s")

    cmd = _build_masscan_cmd(masscan_bin, targets, iface, config)
    log.info(f"Executing: {' '.join(cmd)}")

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )

    # Rich progress bar that advances over estimated scan time
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Host discovery (masscan)...", total=int(est_duration) + 1)
        start = time.monotonic()
        while not progress.finished:
            elapsed = time.monotonic() - start
            progress.update(task, completed=min(elapsed, int(est_duration)))
            try:
                await asyncio.wait_for(asyncio.shield(asyncio.ensure_future(_wait_proc(proc))), timeout=1.0)
                break  # process finished
            except asyncio.TimeoutError:
                pass
        progress.update(task, completed=int(est_duration) + 1)

    # Wait with final timeout
    try:
        await asyncio.wait_for(proc.wait(), timeout=config.discovery_wait + est_duration)
    except asyncio.TimeoutError:
        log.warning("masscan timed out — killing process")
        proc.kill()

    console.print("Converting masscan output...")
    _convert_masscan_output()

    live = _parse_live_hosts(Path("live_hosts.txt"))
    Path("live_hosts.txt").unlink(missing_ok=True)

    console.print(f"\t[bold][ Discovered {len(live)} host(s) ][/bold]\n")
    log.info(f"{len(live)} hosts found: {live}")
    return live


async def _wait_proc(proc: asyncio.subprocess.Process) -> None:
    await proc.wait()


def _build_masscan_cmd(
    masscan_bin: str,
    targets: list[str],
    iface: Optional[str],
    config: Config,
) -> list[str]:
    cmd = [
        masscan_bin,
        *targets,
        f"-p{config.masscan_ports}",
        "--ping",
        "--rate", str(config.masscan_rate),
        "--retries", str(config.masscan_retries),
        "--wait", "10",
        "--open-only",
        "--banners",
        "-oB", "masscan.bin",
    ]
    if iface:
        cmd.extend(["-e", iface])
    return cmd


def _convert_masscan_output() -> None:
    """Convert masscan binary output to text list of live IPs."""
    convert_cmd = (
        "masscan --readscan masscan.bin -oL masscan.txt && "
        "awk '{print $4}' masscan.txt | sort -Vu | sed '/^$/d' > live_hosts.txt"
    )
    subprocess.run(convert_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _parse_live_hosts(path: Path) -> list[str]:
    if not path.exists():
        return []
    hosts = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                ipaddress.ip_address(line)
                hosts.append(line)
            except ValueError:
                log.warning(f"Skipping non-IP in live_hosts.txt: {line!r}")
    return hosts


def _estimate_scan_duration(config: Config, host_count: int) -> float:
    """Approximate per-host masscan time based on port count and rate."""
    num_ports = config.masscan_ports.count(",") + 2 * config.masscan_ports.count("-")
    max_attempts = 1 + config.masscan_retries
    per_host = num_ports * max_attempts / config.masscan_rate
    return max(per_host * host_count, 5.0)


def _count_hosts(targets: list[str]) -> int:
    count = 0
    for t in targets:
        try:
            if "/" in t:
                count += 2 ** (32 - int(t.split("/")[1]))
            else:
                count += 1
        except (ValueError, IndexError):
            count += 1
    return count
