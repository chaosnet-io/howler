"""
Results summarizer.
Runs grep-based summaries (same as original nightcall) and optionally
writes a JSONL findings file from ScanResult objects.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Optional

from models import ScanResult

log = logging.getLogger(__name__)

_GREP_SUMMARIES = [
    # (command, output_file)
    (
        "grep -rH -e '/tcp' -e '/udp' -e '| OS:' -e 'Running:' -e 'OS details:' "
        ". --include='*.nmap' | grep -v -e filtered -e tcpwrapped "
        "> nmap.summary.txt 2>/dev/null",
        "nmap.summary.txt",
    ),
    (
        "grep -H '[+]' msf/*.msf.* > msf.summary.txt 2>/dev/null",
        "msf.summary.txt",
    ),
    (
        "for i in $(grep -L ERROR http/*.whatweb 2>/dev/null); do grep -H Summary $i; done "
        "> http.summary.txt 2>/dev/null",
        "http.summary.txt",
    ),
    (
        "grep -H SUCCESS brute/*.brute > brute.summary.txt 2>/dev/null",
        "brute.summary.txt",
    ),
    # Remove empty summary files
    (
        "find . -maxdepth 2 -type f -name '*summary*' -size 0 -delete 2>/dev/null",
        None,
    ),
]


def run(results: Optional[list[ScanResult]] = None, jsonl_output: bool = True) -> None:
    """
    Run grep-based summaries, then write JSONL findings if enabled.
    """
    log.info("Summarizing results...")

    for cmd, _ in _GREP_SUMMARIES:
        subprocess.run(cmd, shell=True)

    if jsonl_output and results:
        _write_jsonl(results)


def _write_jsonl(results: list[ScanResult]) -> None:
    """Write one JSON object per ScanResult to findings.jsonl."""
    path = Path("findings.jsonl")
    count = 0
    with open(path, "w") as f:
        for r in results:
            if r.returncode == 0 or r.stdout.strip():
                entry = {
                    "host": r.job.host,
                    "category": r.job.category,
                    "tool": r.job.cmd[0] if r.job.cmd else "",
                    "description": r.job.description,
                    "output_file": r.job.output_file,
                    "returncode": r.returncode,
                    "duration": round(r.duration, 2),
                    "timed_out": r.timed_out,
                }
                f.write(json.dumps(entry) + "\n")
                count += 1
    log.info(f"Wrote {count} findings to {path}")
