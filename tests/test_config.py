"""
Tests for config.py — load_config round-trip, tool resolution, and the
SecLists auto-detection that makes Howler portable across distros.

A config bug typically means a silently-ignored setting: a key added to
config.yaml that load_config doesn't wire up just disappears. These tests
pin every documented config field.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

# load_config() silently returns defaults when pyyaml isn't installed. Skip the
# YAML-dependent tests in that case rather than reporting false failures.
yaml = pytest.importorskip("yaml")

from config import Config, load_config


# ── load_config — defaults & overrides ──────────────────────────────────────

def test_load_config_no_yaml_returns_defaults():
    """When no YAML file is found, every field should be the dataclass default."""
    c = load_config(Path("/nonexistent/config.yaml"))
    assert c.concurrent_tasks == 4
    assert c.task_timeout == 3600
    assert c.discovery_wait == 60
    assert c.masscan_rate == 2000
    assert c.masscan_retries == 2
    assert c.nmap_large_host_threshold == 100
    assert c.nmap_version_intensity == 5
    assert c.enable_brute is False
    assert c.enable_web is False
    assert c.jsonl_output is True
    assert c.log_level == "INFO"


def test_load_config_applies_concurrency_overrides(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("""
concurrency:
  concurrent_tasks: 16
  task_timeout: 7200
  discovery_wait: 120
""")
    c = load_config(cfg)
    assert c.concurrent_tasks == 16
    assert c.task_timeout == 7200
    assert c.discovery_wait == 120


def test_load_config_applies_masscan_overrides(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("""
masscan:
  rate: 5000
  retries: 5
  ports: "1-1000"
""")
    c = load_config(cfg)
    assert c.masscan_rate == 5000
    assert c.masscan_retries == 5
    assert c.masscan_ports == "1-1000"


def test_load_config_applies_nmap_overrides(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("""
nmap:
  large_host_threshold: 50
  version_intensity: 7
  max_retries: 1
  max_rtt_timeout: 500ms
  max_scan_delay: 500ms
  nse_tcp: "banner"
  nse_udp: "nbstat"
  udp_ports: "53,161"
""")
    c = load_config(cfg)
    assert c.nmap_large_host_threshold == 50
    assert c.nmap_version_intensity == 7
    assert c.nmap_max_retries == 1
    assert c.nmap_max_rtt_timeout == "500ms"
    assert c.nmap_max_scan_delay == "500ms"
    assert c.nmap_nse_tcp == "banner"
    assert c.nmap_nse_udp == "nbstat"
    assert c.nmap_udp_ports == "53,161"


def test_load_config_applies_wordlist_overrides(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("""
wordlists:
  user_dict: /custom/users.txt
  pass_dict: /custom/pass.txt
  snmp_dict: /custom/snmp.txt
  http_fuzz_small: /custom/small.txt
  http_fuzz_large: /custom/large.txt
""")
    c = load_config(cfg)
    assert c.user_dict == Path("/custom/users.txt")
    assert c.pass_dict == Path("/custom/pass.txt")
    assert c.snmp_dict == Path("/custom/snmp.txt")
    assert c.http_fuzz_small == Path("/custom/small.txt")
    assert c.http_fuzz_large == Path("/custom/large.txt")


def test_load_config_applies_tool_overrides(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("""
tools:
  nmap: /opt/nmap/bin/nmap
  masscan: /usr/local/bin/masscan
""")
    c = load_config(cfg)
    assert c.tool_paths["nmap"] == "/opt/nmap/bin/nmap"
    assert c.tool_paths["masscan"] == "/usr/local/bin/masscan"
    # Tools not in YAML aren't registered → fall through to shutil.which
    assert "hydra" not in c.tool_paths


def test_load_config_null_tool_path_not_registered(tmp_path):
    """A tool set to null in YAML should NOT be registered in tool_paths,
    so config.tool() falls through to shutil.which()."""
    cfg = tmp_path / "config.yaml"
    cfg.write_text("""
tools:
  nmap: null
  hydra: /usr/bin/hydra
""")
    c = load_config(cfg)
    assert "nmap" not in c.tool_paths  # null → not registered
    assert c.tool_paths["hydra"] == "/usr/bin/hydra"


def test_load_config_applies_feature_flags(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("""
features:
  randomize_jobs: true
  jsonl_output: false
""")
    c = load_config(cfg)
    assert c.randomize_jobs is True
    assert c.jsonl_output is False


def test_load_config_applies_log_level(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("""
output:
  log_level: DEBUG
""")
    c = load_config(cfg)
    assert c.log_level == "DEBUG"


def test_load_config_partial_override_keeps_other_defaults(tmp_path):
    """Setting one field in a section shouldn't reset unrelated fields."""
    cfg = tmp_path / "config.yaml"
    cfg.write_text("""
concurrency:
  concurrent_tasks: 8
""")
    c = load_config(cfg)
    assert c.concurrent_tasks == 8
    # task_timeout and discovery_wait untouched
    assert c.task_timeout == 3600
    assert c.discovery_wait == 60


# ── Config.tool() ───────────────────────────────────────────────────────────

def test_tool_returns_override_when_set():
    c = Config()
    c.tool_paths["nmap"] = "/opt/nmap"
    assert c.tool("nmap") == "/opt/nmap"


def test_tool_returns_none_when_not_set_and_which_disabled():
    """With shutil.which patched to None (via conftest autouse fixture),
    a tool not in tool_paths returns None."""
    c = Config()
    assert c.tool("nonexistent-tool") is None


def test_tool_available_checks_truthiness():
    c = Config()
    assert c.tool_available("missing") is False
    c.tool_paths["present"] = "/bin/true"
    assert c.tool_available("present") is True


# ── resolve_wordlist ────────────────────────────────────────────────────────

def test_resolve_wordlist_existing_file_returned(tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_text("admin\n")
    c = Config()
    result = c.resolve_wordlist(wl)
    assert result == wl


def test_resolve_wordlist_missing_file_no_seclists_returns_none(tmp_path):
    c = Config()
    with patch("config._detect_seclists_roots", return_value=()):
        result = c.resolve_wordlist(tmp_path / "nonexistent.txt")
    assert result is None


def test_resolve_wordlist_reroots_against_seclists_install(tmp_path):
    """A path like /usr/share/seclists/Foo/bar.txt should be re-rooted against
    any detected SecLists install when the original path doesn't exist."""
    seclists_root = tmp_path / "seclists"
    (seclists_root / "Discovery" / "Web-Content").mkdir(parents=True)
    target = seclists_root / "Discovery" / "Web-Content" / "common.txt"
    target.write_text("admin\n")

    c = Config()
    # Original path doesn't exist, but the suffix under seclists/ should match
    configured = Path("/usr/share/seclists/Discovery/Web-Content/common.txt")
    with patch("config._detect_seclists_roots", return_value=(seclists_root,)):
        result = c.resolve_wordlist(configured)
    assert result == target


def test_resolve_wordlist_explicit_env_var(tmp_path):
    """HOWLER_SECLISTS env var is checked first in _detect_seclists_roots."""
    import os
    custom_root = tmp_path / "custom-seclists"
    (custom_root / "Passwords").mkdir(parents=True)
    target = custom_root / "Passwords" / "unix_passwords.txt"
    target.write_text("password\n")

    c = Config()
    configured = Path("/usr/share/seclists/Passwords/unix_passwords.txt")
    old = os.environ.get("HOWLER_SECLISTS")
    try:
        os.environ["HOWLER_SECLISTS"] = str(custom_root)
        result = c.resolve_wordlist(configured)
    finally:
        if old is not None:
            os.environ["HOWLER_SECLISTS"] = old
        else:
            os.environ.pop("HOWLER_SECLISTS", None)
    assert result == target
