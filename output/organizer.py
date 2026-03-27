"""
Output file organizer.
Moves scan output files into categorized subdirectories after each scan phase.
Mirrors the original nightcall cleanup() behaviour, driven by Job.category.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

# Shell move commands run after nmap completes (sorts XML and nmap text files)
_POST_NMAP_CMDS = [
    "mkdir -p xml && mv -f *.xml xml/ 2>/dev/null || true",
    "mkdir -p nmap && mv -f *.nmap nmap/ 2>/dev/null || true",
    "mkdir -p nmap/gnmap && mv -f *.gnmap nmap/gnmap/ 2>/dev/null || true",
]

# Shell move commands run at the very end (sorts everything else)
_FINAL_CMDS = [
    "mkdir -p msf && mv -f *.msf.* msf/ 2>/dev/null || true",
    "mkdir -p misc && mv -f *.misc.* misc/ 2>/dev/null || true",
    "mkdir -p misc/ssl && mv -f misc/*.ssl misc/ssl/ 2>/dev/null || true",
    "mkdir -p http && mv -f *.http*.* http/ 2>/dev/null || true",
    "mkdir -p http && mv -f *.waf http/ *.whatweb http/ *.nikto http/ *.ffuf http/ *.wpscan http/ *.joomscan http/ 2>/dev/null || true",
    "mkdir -p http/images && mv -f *.png http/images/ 2>/dev/null || true",
    "mkdir -p brute && mv -f *.brute brute/ 2>/dev/null || true",
    # Remove leftover .msf.* from brute dir if any ended up there
    "mv -f brute/*.msf.* msf/ 2>/dev/null || true",
    "find . -type d -maxdepth 3 -empty -delete 2>/dev/null || true",
]


def post_nmap_cleanup() -> None:
    """Sort nmap output into xml/ and nmap/ directories."""
    log.info("Sorting nmap output...")
    _run_cmds(_POST_NMAP_CMDS)


def final_cleanup() -> None:
    """Sort all remaining output files into their subdirectories."""
    log.info("Sorting final output...")
    _run_cmds(_FINAL_CMDS)


def _run_cmds(cmds: list[str]) -> None:
    for cmd in cmds:
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode not in (0, 1):  # 1 is common from mv with no matches
            log.debug(f"Cleanup command exited {result.returncode}: {cmd}")
