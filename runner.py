"""
Async job runner for Howler.
Uses asyncio.Semaphore for concurrency control and
asyncio.create_subprocess_exec (no shell=True) for process spawning.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from config import Config
from models import Job, ScanResult

log = logging.getLogger(__name__)


class AsyncJobRunner:
    def __init__(self, config: Config, console: Console) -> None:
        self.config = config
        self.console = console

    async def run_all(self, jobs: list[Job], label: str = "Scanning") -> list[ScanResult]:
        """Run all jobs concurrently, bounded by config.concurrent_tasks."""
        if not jobs:
            return []

        if self.config.randomize_jobs:
            jobs = list(jobs)
            random.shuffle(jobs)

        sem = asyncio.Semaphore(self.config.concurrent_tasks)
        results: list[Optional[ScanResult]] = [None] * len(jobs)

        with Progress(
            SpinnerColumn(),
            TextColumn(f"[bold]{label}[/bold] {{task.description}}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        ) as progress:
            task_id = progress.add_task("", total=len(jobs))

            async def _run_and_record(idx: int, job: Job) -> None:
                result = await self._run_one(job, sem)
                results[idx] = result
                progress.advance(task_id)
                progress.update(task_id, description=f"[dim]{job.host}[/dim]")

            await asyncio.gather(*[_run_and_record(i, j) for i, j in enumerate(jobs)])

        return [r for r in results if r is not None]

    async def _run_one(self, job: Job, sem: asyncio.Semaphore) -> ScanResult:
        """Execute a single job, respecting the semaphore and timeout."""
        async with sem:
            log.info(f"Executing: {' '.join(job.cmd)}")
            start = time.monotonic()
            timed_out = False

            if job.shell:
                # Escape hatch for unavoidable shell pipelines (masscan convert, etc.)
                proc = await asyncio.create_subprocess_shell(
                    " ".join(job.cmd),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *job.cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                except FileNotFoundError as e:
                    log.warning(f"Tool not found for job {job.description!r}: {e}")
                    return ScanResult(
                        job=job, returncode=-1,
                        stdout="", stderr=str(e),
                        duration=0.0, timed_out=False,
                    )

            timeout = job.timeout or self.config.task_timeout
            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=float(timeout)
                )
            except asyncio.TimeoutError:
                log.warning(f"Timeout ({timeout}s) exceeded: {job.description!r}")
                timed_out = True
                try:
                    proc.kill()
                    await proc.wait()
                except ProcessLookupError:
                    pass
                stdout_b, stderr_b = b"", b""

            duration = time.monotonic() - start
            returncode = proc.returncode or 0

            stdout = stdout_b.decode("utf-8", errors="replace")
            stderr = stderr_b.decode("utf-8", errors="replace")

            if returncode != 0 and stderr.strip():
                log.debug(f"StdErr [{job.description}]: {stderr[:500]}")

            log.info(f"Completed ({duration:.1f}s rc={returncode}): {job.description!r}")

            # Write stdout to output_file for tools that don't write their own file
            # (e.g. whatweb, wafw00f). Tools like ffuf/nmap write their own file via
            # -o/-oA flags, so we skip if the file already exists.
            if job.output_file and stdout.strip():
                out_path = Path(job.output_file)
                if not out_path.exists():
                    try:
                        out_path.write_text(stdout, encoding="utf-8", errors="replace")
                    except OSError as e:
                        log.warning(f"Could not write output file {out_path}: {e}")

            return ScanResult(
                job=job,
                returncode=returncode,
                stdout=stdout,
                stderr=stderr,
                duration=duration,
                timed_out=timed_out,
            )
