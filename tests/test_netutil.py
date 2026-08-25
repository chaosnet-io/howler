"""
Tests for netutil.py — the address-family helpers shared by the pipeline and
the modules. These pin the IPv4/IPv6 classification and the bracketing /
filename-sanitizing behavior that the IPv6 work depends on.
"""
from __future__ import annotations

from netutil import (
    MAX_IPV6_EXPAND_PREFIX,
    bracket,
    hostport,
    is_ipv4,
    is_ipv6,
    safe_filename,
    split_by_family,
)


def test_is_ipv4_bare_address():
    assert is_ipv4("10.0.0.1")
    assert not is_ipv4("2001:db8::1")


def test_is_ipv6_bare_address():
    assert is_ipv6("2001:db8::1")
    assert not is_ipv6("10.0.0.1")


def test_family_detection_accepts_cidr():
    assert is_ipv4("10.0.0.0/24")
    assert is_ipv6("2001:db8::/120")
    assert not is_ipv6("10.0.0.0/24")
    assert not is_ipv4("2001:db8::/120")


def test_bracket_ipv6_only():
    assert bracket("2001:db8::1") == "[2001:db8::1]"
    assert bracket("10.0.0.1") == "10.0.0.1"


def test_hostport():
    assert hostport("2001:db8::1", "443") == "[2001:db8::1]:443"
    assert hostport("10.0.0.1", "443") == "10.0.0.1:443"


def test_safe_filename_ipv6_replaces_colons():
    assert safe_filename("2001:db8::1") == "2001_db8__1"
    assert safe_filename("::1") == "__1"


def test_safe_filename_ipv4_unchanged():
    assert safe_filename("10.0.0.1") == "10.0.0.1"


def test_split_by_family_mixed_list():
    ipv4, ipv6 = split_by_family(
        ["10.0.0.1", "2001:db8::1", "10.0.0.0/24", "2001:db8::/120"]
    )
    assert ipv4 == ["10.0.0.1", "10.0.0.0/24"]
    assert ipv6 == ["2001:db8::1", "2001:db8::/120"]


def test_split_by_family_empty():
    ipv4, ipv6 = split_by_family([])
    assert ipv4 == [] and ipv6 == []


def test_max_ipv6_expand_prefix_is_120():
    assert MAX_IPV6_EXPAND_PREFIX == 120
