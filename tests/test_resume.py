"""
Tests for the resume subsystem.

Resume lets users re-run an interrupted scan without redoing jobs that
already completed successfully. The state file is findings.jsonl, written
incrementally by the runner (one line per completed job). On --resume, the
runner skips any job whose description maps to status="ok" in the prior state.

These tests pin:
- The pure filter function (the only resume logic that's easily unit-testable)
- Job.description uniqueness across every built-in module — the resume key
- load_resume_state parsing behaviour (tolerates malformed lines, missing file)
- reset_findings_for_fresh_run truncation

The runner's incremental-write behaviour is integration-tested informally
(it spawns subprocesses); the unit-testable surface is filter_completed_jobs
+ load_resume_state + the description-uniqueness invariant.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

import pytest

from config import Config
from models import Job, PortInfo
from modules import build_default_registry
from runner import filter_completed_jobs


HOST = "10.10.10.5"


# ── filter_completed_jobs ───────────────────────────────────────────────────

def _job(desc: str, host: str = HOST) -> Job:
    """Build a minimal Job for testing — only description matters for resume."""
    return Job(
        cmd=["tool"],
        output_file="out",
        category="misc",
        host=host,
        description=desc,
    )


def test_filter_skips_ok_jobs_only():
    jobs = [_job("a"), _job("b"), _job("c")]
    state = {"a": "ok", "b": "ok"}
    kept, skipped = filter_completed_jobs(jobs, state)
    assert [j.description for j in kept] == ["c"]
    assert skipped == 2


def test_filter_reruns_failed_jobs():
    """failed jobs must be re-run, not skipped."""
    jobs = [_job("a"), _job("b")]
    state = {"a": "failed", "b": "ok"}
    kept, skipped = filter_completed_jobs(jobs, state)
    assert [j.description for j in kept] == ["a"]
    assert skipped == 1


def test_filter_reruns_timeout_jobs():
    """timeout jobs must be re-run, not skipped."""
    jobs = [_job("a")]
    state = {"a": "timeout"}
    kept, skipped = filter_completed_jobs(jobs, state)
    assert kept == [jobs[0]]
    assert skipped == 0


def test_filter_empty_state_runs_everything():
    jobs = [_job("a"), _job("b"), _job("c")]
    kept, skipped = filter_completed_jobs(jobs, {})
    assert kept == jobs
    assert skipped == 0


def test_filter_unknown_descriptions_run_everything():
    """If state has descriptions that don't match any current job, ignore."""
    jobs = [_job("a"), _job("b")]
    state = {"x": "ok", "y": "ok", "z": "ok"}
    kept, skipped = filter_completed_jobs(jobs, state)
    assert kept == jobs
    assert skipped == 0


def test_filter_preserves_job_order():
    """Order of kept jobs must match input order — the runner relies on it
    for stable progress bars and (in --randomize_jobs mode) reproducible runs."""
    jobs = [_job(f"job-{i}") for i in range(10)]
    state = {f"job-{i}": "ok" for i in (1, 3, 5, 7)}
    kept, skipped = filter_completed_jobs(jobs, state)
    assert [j.description for j in kept] == [
        "job-0", "job-2", "job-4", "job-6", "job-8", "job-9",
    ]
    assert skipped == 4


def test_filter_does_not_mutate_inputs():
    jobs = [_job("a"), _job("b")]
    state = {"a": "ok"}
    original_jobs = list(jobs)
    filter_completed_jobs(jobs, state)
    assert jobs == original_jobs


# ── Job.description uniqueness — the resume key invariant ──────────────────

def test_descriptions_unique_per_module(config, port):
    """Resume keys must be unambiguous: any duplicate descriptions must be
    "safe duplicates" — identical cmd AND output_file (e.g. enum4linux-ng
    runs on both 139 and 445, but the cmd is the same since the tool doesn't
    take a port). On --resume, both skip together, which is correct because
    their output is interchangeable.

    A *real* collision — same description but different cmd or output_file —
    would be a resume bug: the second job's distinct output would be lost
    on resume. Fail loudly if that happens.
    """
    registry = build_default_registry()
    from modules.brute import BruteModule
    brute = BruteModule()

    config.enable_web = True
    config.enable_brute = True

    # Exhaustive port matrix: every portid/proto/name/product/ssl/cms combo a
    # built-in module claims to handle. Generates all jobs a real scan might.
    test_ports = [
        port(portid="22", protocol="tcp", name="ssh", ssl=True),
        port(portid="80", protocol="tcp", name="http", product=""),
        port(portid="443", protocol="tcp", name="https", ssl=True),
        port(portid="8443", protocol="tcp", name="https-alt", ssl=True),
        port(portid="8080", protocol="tcp", name="http-proxy", product="apache tomcat", cms="Wordpress"),
        port(portid="53", protocol="tcp", name="domain"),
        port(portid="53", protocol="udp", name="domain"),
        port(portid="139", protocol="tcp", name="netbios-ssn"),
        port(portid="445", protocol="tcp", name="microsoft-ds"),
        port(portid="25", protocol="tcp", name="smtp"),
        port(portid="465", protocol="tcp", name="smtps", ssl=True),
        port(portid="161", protocol="udp", name="snmp"),
        port(portid="2049", protocol="tcp", name="nfs"),
        port(portid="2049", protocol="udp", name="nfs"),
        port(portid="500", protocol="udp", name="isakmp"),
        port(portid="4500", protocol="udp", name="nat-t-ike"),
        port(portid="623", protocol="udp", name="rmcp"),
        port(portid="69", protocol="udp", name="tftp"),
        # Windows / AD coverage
        port(portid="21", protocol="tcp", name="ftp"),
        port(portid="389", protocol="tcp", name="ldap"),
        port(portid="636", protocol="tcp", name="ldapssl"),
        port(portid="3268", protocol="tcp", name="globalcataLDAP"),
        port(portid="88", protocol="tcp", name="kerberos"),
        port(portid="5985", protocol="tcp", name="wsman"),
        port(portid="5986", protocol="tcp", name="wsman"),
        port(portid="3389", protocol="tcp", name="ms-wbt-server"),
    ]

    # Map description → set of (cmd, output_file, category) tuples.
    # A "safe duplicate" has exactly one tuple in its set (all jobs sharing
    # this description are identical). A "real collision" has 2+ tuples.
    by_desc: dict[str, set[tuple[tuple[str, ...], str, str]]] = {}

    for p in test_ports:
        for module in registry.all_modules():
            if not module.match(p):
                continue
            for job in module.jobs(HOST, p, config):
                key = job.description
                ident = (tuple(job.cmd), job.output_file, job.category)
                by_desc.setdefault(key, set()).add(ident)
        if brute.match(p):
            for job in brute.jobs(HOST, p, config):
                key = job.description
                ident = (tuple(job.cmd), job.output_file, job.category)
                by_desc.setdefault(key, set()).add(ident)

    real_collisions = {
        desc: idents for desc, idents in by_desc.items() if len(idents) > 1
    }
    assert not real_collisions, (
        "Resume-key collisions: descriptions match jobs with different "
        f"cmd/output_file — resume would skip the wrong job. {real_collisions}"
    )

    # Safe duplicates are allowed (wasted work, but resume-correct). Surface
    # them so future optimisations can target them deliberately.
    safe_dups = {desc: idents for desc, idents in by_desc.items()
                 if len(idents) == 1 and len({d for d, _, _ in [next(iter(idents))]}) > 0}
    # (no assertion — just noting they exist; e.g. enum4linux-ng on 139+445,
    # showmount on 2049/tcp+udp)


# ── load_resume_state ───────────────────────────────────────────────────────

def test_load_resume_state_reads_findings_jsonl(tmp_path, monkeypatch):
    """load_resume_state returns {description: status} from findings.jsonl."""
    findings = tmp_path / "findings.jsonl"
    findings.write_text(
        json.dumps({"description": "nmap TCP 1.1.1.1", "status": "ok"}) + "\n"
        + json.dumps({"description": "testssl.sh 1.1.1.1:443", "status": "failed"}) + "\n"
        + json.dumps({"description": "hydra ssh 1.1.1.1:22", "status": "timeout"}) + "\n"
    )
    import howler
    monkeypatch.setattr(howler, "FINDINGS_PATH", findings)
    state = howler.load_resume_state()
    assert state == {
        "nmap TCP 1.1.1.1": "ok",
        "testssl.sh 1.1.1.1:443": "failed",
        "hydra ssh 1.1.1.1:22": "timeout",
    }


def test_load_resume_state_missing_file_returns_empty(tmp_path, monkeypatch):
    import howler
    monkeypatch.setattr(howler, "FINDINGS_PATH", tmp_path / "nonexistent.jsonl")
    assert howler.load_resume_state() == {}


def test_load_resume_state_skips_malformed_lines(tmp_path, monkeypatch):
    """Malformed JSON lines must be skipped, not crash the load."""
    findings = tmp_path / "findings.jsonl"
    findings.write_text(
        json.dumps({"description": "good", "status": "ok"}) + "\n"
        + "not valid json at all\n"
        + "\n"  # blank line
        + json.dumps({"description": "also good", "status": "failed"}) + "\n"
    )
    import howler
    monkeypatch.setattr(howler, "FINDINGS_PATH", findings)
    state = howler.load_resume_state()
    assert state == {"good": "ok", "also good": "failed"}


def test_load_resume_state_skips_entries_without_description(tmp_path, monkeypatch):
    """Entries missing description or status are ignored — can't resume-key them."""
    findings = tmp_path / "findings.jsonl"
    findings.write_text(
        json.dumps({"status": "ok"}) + "\n"
        + json.dumps({"description": "no status"}) + "\n"
        + json.dumps({"description": "good", "status": "ok"}) + "\n"
    )
    import howler
    monkeypatch.setattr(howler, "FINDINGS_PATH", findings)
    state = howler.load_resume_state()
    assert state == {"good": "ok"}


def test_load_resume_state_last_entry_wins(tmp_path, monkeypatch):
    """If findings.jsonl has duplicate descriptions (shouldn't happen in normal
    use, but defensive), the last entry wins — consistent with append semantics."""
    findings = tmp_path / "findings.jsonl"
    findings.write_text(
        json.dumps({"description": "job", "status": "failed"}) + "\n"
        + json.dumps({"description": "job", "status": "ok"}) + "\n"
    )
    import howler
    monkeypatch.setattr(howler, "FINDINGS_PATH", findings)
    assert howler.load_resume_state() == {"job": "ok"}


# ── reset_findings_for_fresh_run ────────────────────────────────────────────

def test_reset_findings_removes_existing_file(tmp_path, monkeypatch):
    findings = tmp_path / "findings.jsonl"
    findings.write_text("stale data\n")
    import howler
    monkeypatch.setattr(howler, "FINDINGS_PATH", findings)
    howler.reset_findings_for_fresh_run()
    assert not findings.exists()


def test_reset_findings_no_op_when_missing(tmp_path, monkeypatch):
    """Removing a non-existent findings.jsonl must not raise."""
    import howler
    monkeypatch.setattr(howler, "FINDINGS_PATH", tmp_path / "nonexistent.jsonl")
    howler.reset_findings_for_fresh_run()  # should not raise


# ── _result_to_entry (the JSONL record shape) ───────────────────────────────

def test_result_to_entry_ok_status():
    from runner import _result_to_entry
    from models import ScanResult
    job = Job(cmd=["tool", "arg"], output_file="out", category="misc",
              host="1.1.1.1", description="tool 1.1.1.1")
    r = ScanResult(job=job, returncode=0, stdout="", stderr="",
                   duration=1.5, timed_out=False)
    entry = _result_to_entry(r)
    assert entry["status"] == "ok"
    assert entry["tool"] == "tool"
    assert entry["host"] == "1.1.1.1"
    assert entry["description"] == "tool 1.1.1.1"
    assert entry["duration"] == 1.5
    assert entry["timed_out"] is False


def test_result_to_entry_failed_status():
    from runner import _result_to_entry
    from models import ScanResult
    job = Job(cmd=["tool"], output_file="out", category="misc",
              host="h", description="d")
    r = ScanResult(job=job, returncode=2, stdout="", stderr="boom",
                   duration=0.1, timed_out=False)
    assert _result_to_entry(r)["status"] == "failed"


def test_result_to_entry_timeout_status():
    from runner import _result_to_entry
    from models import ScanResult
    job = Job(cmd=["tool"], output_file="out", category="misc",
              host="h", description="d")
    r = ScanResult(job=job, returncode=-1, stdout="", stderr="",
                   duration=3600.0, timed_out=True)
    assert _result_to_entry(r)["status"] == "timeout"
