"""
Async job runner for Howler.
Uses asyncio.Semaphore for concurrency control and
asyncio.create_subprocess_exec (no shell=True) for process spawning.

Resume semantics
----------------
``run_all`` accepts an optional ``resume_state`` mapping ``Job.description``
to its prior ``status`` ("ok" | "failed" | "timeout") from a previous run's
``run_state.jsonl``. Only ``ok`` jobs are skipped; ``failed`` and ``timeout``
jobs are re-run. ``run_state.jsonl`` is written incrementally as each job
completes so a crash (or Ctrl-C) leaves a usable resume state on disk.
"""

from __future__ import annotations

import asyncio
import json
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


def filter_completed_jobs(
    jobs: list[Job],
    resume_state: dict[str, str],
) -> tuple[list[Job], int]:
    """Split ``jobs`` into those still to run vs. previously completed.

    The resume key is ``Job.description`` — it's already in run_state.jsonl
    (so existing files work without a migration) and is unique per
    (tool, host, port, variant) across every built-in module.

    Only ``status == "ok"`` causes a skip. ``failed`` and ``timeout`` entries
    are dropped by the caller before they reach us, so any non-"ok" entry here
    means the prior run was interrupted mid-job — re-run it.

    Returns ``(kept_jobs, skipped_count)``.
    """
    kept: list[Job] = []
    skipped = 0
    for job in jobs:
        if resume_state.get(job.description) == "ok":
            skipped += 1
        else:
            kept.append(job)
    return kept, skipped


def _result_to_entry(r: ScanResult) -> dict:
    """Serialise a ScanResult to the JSONL record written to run_state.jsonl."""
    if r.timed_out:
        status = "timeout"
    elif r.returncode == 0:
        status = "ok"
    else:
        status = "failed"
    return {
        "host": r.job.host,
        "category": r.job.category,
        "tool": r.job.cmd[0] if r.job.cmd else "",
        "description": r.job.description,
        "output_file": r.job.output_file,
        "returncode": r.returncode,
        "status": status,
        "duration": round(r.duration, 2),
        "timed_out": r.timed_out,
    }


class AsyncJobRunner:
    def __init__(self, config: Config, console: Console) -> None:
        self.config = config
        self.console = console

    async def run_all(
        self,
        jobs: list[Job],
        label: str = "Scanning",
        resume_state: Optional[dict[str, str]] = None,
        findings_path: str = "run_state.jsonl",
    ) -> list[ScanResult]:
        """Run all jobs concurrently, bounded by config.concurrent_tasks.

        If ``resume_state`` is non-empty, jobs whose description maps to
        ``"ok"`` are skipped (their output files are assumed still on disk).
        ``run_state.jsonl`` is opened in append mode and one record is written
        per completed job — so a SIGKILL mid-run leaves a usable state.
        """
        if not jobs:
            return []

        if resume_state:
            jobs, skipped = filter_completed_jobs(jobs, resume_state)
            if skipped:
                self.console.print(
                    f"[dim]Resume: skipping {skipped} previously completed "
                    f"job(s) for this phase[/dim]"
                )
            if not jobs:
                self.console.print("[dim]Resume: nothing left to do for this phase[/dim]")
                return []

        if self.config.randomize_jobs:
            jobs = list(jobs)
            random.shuffle(jobs)

        sem = asyncio.Semaphore(self.config.concurrent_tasks)
        results: list[Optional[ScanResult]] = [None] * len(jobs)
        write_lock = asyncio.Lock()
        findings_file = open(findings_path, "a", encoding="utf-8")

        try:
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
                    # Append to run_state.jsonl immediately so a crash leaves
                    # a usable resume state. Serialised by write_lock.
                    async with write_lock:
                        findings_file.write(
                            json.dumps(_result_to_entry(result)) + "\n"
                        )
                        findings_file.flush()
                    progress.advance(task_id)
                    progress.update(task_id, description=f"[dim]{job.host}[/dim]")

                await asyncio.gather(*[_run_and_record(i, j) for i, j in enumerate(jobs)])
        finally:
            findings_file.close()

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
            # Only capture stdout on success: a failed tool typically dumps its
            # usage/help to stdout, and writing that produces convincing-looking
            # stub files that hide the failure (see summarizer 'status' field).
            if job.output_file and returncode == 0 and not timed_out and stdout.strip():
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
