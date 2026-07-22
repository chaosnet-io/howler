"""
Shared fixtures for the Howler test suite.

Design notes
------------
- ``shutil.which`` is patched to return ``None`` for every test (autouse fixture).
  ``Config.tool()`` only resolves a tool when its path is explicitly registered
  in ``config.tool_paths``. This keeps tests deterministic: a passing test on a
  Kali box with every tool installed also passes on a bare CI runner.
- The ``config`` fixture yields a fresh ``Config`` with every tool registered to
  a fake path and wordlists pointing at real (temp) files, so the ``.exists()``
  guards in BruteModule / SmtpModule / SnmpModule / HttpModule pass. Tests that
  need a tool to be "missing" just ``pop`` it from ``tool_paths``.
- The ``port`` fixture is a *factory* (not a PortInfo instance) so tests can
  build several ports with different fields in one function.
"""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Callable

import pytest

from config import Config
from models import PortInfo


# Every tool name referenced anywhere in the codebase. Registering all of them
# in tool_paths means config.tool(name) returns a fake path without ever calling
# shutil.which.
_ALL_TOOLS = (
    "masscan", "nmap", "ffuf", "gowitness", "nikto", "whatweb", "wafw00f",
    "wpscan", "joomscan", "testssl.sh", "enum4linux-ng", "hydra",
    "ssh-audit", "smtp-user-enum", "dnsrecon", "ike-scan", "showmount",
    "onesixtyone", "ipmitool",
)


@pytest.fixture(autouse=True)
def _no_real_tool_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force ``shutil.which`` to always return None.

    Without this, tests would silently depend on the host's installed tools:
    a test expecting ``config.tool('nmap')`` to return None would pass on a
    machine without nmap and fail on one that has it.
    """
    monkeypatch.setattr(shutil, "which", lambda _name: None)


@pytest.fixture
def config(tmp_path: Path) -> Config:
    """A fresh Config: all tools available (fake paths), real temp wordlists.

    ``enable_brute`` and ``enable_web`` are False by default — opt in per test.
    """
    c = Config()
    for tool in _ALL_TOOLS:
        c.tool_paths[tool] = f"/fake/{tool}"

    # BruteModule / SmtpModule / SnmpModule / HttpModule check .exists() on
    # these. Use real temp files so those guards pass by default.
    for attr in ("user_dict", "pass_dict", "snmp_dict", "http_fuzz_small", "http_fuzz_large"):
        p = tmp_path / f"{attr}.txt"
        p.write_text("placeholder\n")
        setattr(c, attr, p)

    c.enable_brute = False
    c.enable_web = False
    c.large_test = False
    return c


@pytest.fixture
def port() -> Callable[..., PortInfo]:
    """Factory for PortInfo with sensible defaults.

    Usage: ``p = port(portid="443", ssl=True)`` — only override what differs.
    """
    def _make(**kwargs) -> PortInfo:
        defaults = dict(
            portid="80",
            protocol="tcp",
            name="http",
            product="",
            version="",
            ssl=False,
            cms="",
        )
        defaults.update(kwargs)
        return PortInfo(**defaults)
    return _make
