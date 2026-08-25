"""
IPv6 plumbing across the pipeline: bounded CIDR expansion, family-safe host
counting, and the masscan exclude-file split (IPv4-only for masscan).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from models import HostScan
from scanner.discovery import _count_hosts, _masscan_exclude_file


# ── expand_cidrs ─────────────────────────────────────────────────────────────

def test_expand_cidrs_ipv6_small_prefix_expands():
    from howler import expand_cidrs

    hosts = {"2001:db8::/126": HostScan(address="2001:db8::/126")}
    expand_cidrs(hosts)
    assert "2001:db8::/126" not in hosts
    assert set(hosts) == {"2001:db8::1", "2001:db8::2", "2001:db8::3"}


def test_expand_cidrs_ipv4_unchanged():
    from howler import expand_cidrs

    hosts = {"10.0.0.0/30": HostScan(address="10.0.0.0/30")}
    expand_cidrs(hosts)
    assert set(hosts) == {"10.0.0.1", "10.0.0.2"}


def test_expand_cidrs_ipv6_large_prefix_refused():
    from howler import expand_cidrs

    hosts = {"2001:db8::/64": HostScan(address="2001:db8::/64")}
    with pytest.raises(SystemExit):
        expand_cidrs(hosts)


def test_expand_cidrs_single_address_untouched():
    from howler import expand_cidrs

    hosts = {"2001:db8::5": HostScan(address="2001:db8::5")}
    expand_cidrs(hosts)
    assert list(hosts) == ["2001:db8::5"]


# ── _count_hosts ─────────────────────────────────────────────────────────────

def test_count_hosts_ipv4_cidr():
    assert _count_hosts(["10.0.0.0/24"]) == 256


def test_count_hosts_ipv6_cidr_family_safe():
    # The old 2**(32 - prefix) arithmetic would be nonsense here.
    assert _count_hosts(["2001:db8::/120"]) == 256


def test_count_hosts_single_addresses():
    assert _count_hosts(["10.0.0.1", "2001:db8::1"]) == 2


# ── _masscan_exclude_file ────────────────────────────────────────────────────

def test_masscan_exclude_file_ipv4_only_returns_original(tmp_path):
    src = tmp_path / "scope.txt"
    src.write_text("10.0.0.0/24\n192.168.1.1\n")
    assert _masscan_exclude_file(str(src)) == str(src)


def test_masscan_exclude_file_mixed_writes_ipv4_only(tmp_path):
    src = tmp_path / "scope.txt"
    src.write_text("10.0.0.0/24\n2001:db8::/120\n192.168.1.1\n# comment\n")
    out = _masscan_exclude_file(str(src))
    try:
        assert out != str(src)
        content = Path(out).read_text()
        assert "10.0.0.0/24" in content
        assert "192.168.1.1" in content
        assert "2001:db8::" not in content
        assert "# comment" in content
    finally:
        Path(out).unlink(missing_ok=True)


def test_masscan_exclude_file_missing_returns_original(tmp_path):
    missing = tmp_path / "does-not-exist.txt"
    assert _masscan_exclude_file(str(missing)) == str(missing)
