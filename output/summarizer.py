"""
Results summarizer.
Runs grep-based summaries (same as original nightcall) and reports a tally
of jobs that did not complete successfully by reading findings.jsonl.

The runner now writes findings.jsonl incrementally as each job completes —
this module no longer owns that file. It just runs the grep summaries and
prints a warning count derived from the on-disk state.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Optional

from models import ScanResult

log = logging.getLogger(__name__)

_FINDINGS_PATH = Path("findings.jsonl")

_GREP_SUMMARIES = [
    # (command, output_file)
    (
        "grep -rH -e '/tcp' -e '/udp' -e '| OS:' -e 'Running:' -e 'OS details:' "
        ". --include='*.nmap' | grep -v -e filtered -e tcpwrapped "
        "> nmap.summary.txt 2>/dev/null",
        "nmap.summary.txt",
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
    """Run grep-based summaries, then warn about non-ok jobs.

    ``results`` and ``jsonl_output`` are accepted for backward compatibility
    but no longer drive the JSONL write — the runner owns findings.jsonl now.
    The warning tally is read from findings.jsonl on disk so it reflects every
    job in the current scan, including ones skipped via --resume.
    """
    log.info("Summarizing results...")

    for cmd, _ in _GREP_SUMMARIES:
        subprocess.run(cmd, shell=True)

    _warn_failed_jobs()


def _warn_failed_jobs() -> None:
    """Tally non-ok jobs from findings.jsonl and log a warning if any.

    Silently no-ops if findings.jsonl is absent (e.g. user deleted it).
    """
    if not _FINDINGS_PATH.exists():
        return

    total = 0
    failed = 0
    try:
        with open(_FINDINGS_PATH) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                total += 1
                if entry.get("status") != "ok":
                    failed += 1
    except OSError as e:
        log.debug(f"could not read findings.jsonl for failure tally: {e}")
        return

    log.info(f"findings.jsonl contains {total} entries")
    if failed:
        log.warning(
            f"{failed} of {total} jobs did not complete successfully "
            f"(non-zero exit or timeout). Inspect 'status' in "
            f"{_FINDINGS_PATH} before trusting coverage."
        )
