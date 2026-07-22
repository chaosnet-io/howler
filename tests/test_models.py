"""
Tests for models.py: PortInfo properties and HostScan behaviour.

These are the pure-data tests — no I/O, no tools, no fixtures beyond the
``port`` factory. They pin the port-classification heuristics that every module
relies on: a wrong ``is_http`` or ``scheme`` here means silent under-coverage
in the field (a web port that doesn't get scanned by the http module).
"""
from __future__ import annotations

import pytest

from models import HostScan, PortInfo


# ── port_key ────────────────────────────────────────────────────────────────

def test_port_key_tcp(port):
    assert port(portid="80", protocol="tcp").port_key == "80/tcp"


def test_port_key_udp(port):
    assert port(portid="161", protocol="udp").port_key == "161/udp"


# ── scheme ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("portid", ["443", "8443"])
def test_scheme_https_by_port(port, portid):
    assert port(portid=portid, ssl=False).scheme == "https"


def test_scheme_https_by_ssl_flag(port):
    assert port(portid="8080", ssl=True).scheme == "https"


def test_scheme_http_default(port):
    assert port(portid="80", ssl=False).scheme == "http"


# ── is_http — port-based detection ──────────────────────────────────────────

@pytest.mark.parametrize("portid", ["80", "443", "8080", "8443", "8000", "8008"])
def test_is_http_by_well_known_port(port, portid):
    """The hardcoded port set should all be detected as HTTP."""
    assert port(portid=portid, name="", product="").is_http is True


@pytest.mark.xfail(
    reason="8888 is in masscan_ports but not in the is_http port set; only "
           "matches if nmap identifies the service as http. Known coverage gap.",
    strict=True,
)
def test_is_http_gap_port_8888(port):
    assert port(portid="8888", name="", product="").is_http is True


# ── is_http — service-name and product detection ────────────────────────────

def test_is_http_by_service_name(port):
    assert port(portid="12345", name="http", product="").is_http is True


def test_is_http_by_product(port):
    assert port(portid="12345", name="unknown", product="Apache httpd").is_http is True


def test_is_http_excluded_by_httpapi_product(port):
    """Products containing 'httpapi' are excluded (e.g. RPC-over-HTTP)."""
    assert port(portid="80", name="http", product="httpapi").is_http is False


def test_is_http_excluded_by_rpc_product(port):
    assert port(portid="80", name="http", product="ncacn_http rpc").is_http is False


def test_is_http_non_http_port(port):
    assert port(portid="22", name="ssh", product="OpenSSH").is_http is False


def test_is_http_excluded_product_takes_precedence_over_name(port):
    """Even with name='http', an httpapi/rpc product should exclude."""
    assert port(portid="80", name="http", product="httpapi").is_http is False


# ── HostScan ────────────────────────────────────────────────────────────────

def test_hostscan_empty_has_no_ports():
    scan = HostScan(address="10.0.0.1")
    assert scan.has_ports() is False
    assert scan.ports == {}


def test_hostscan_add_port(port):
    scan = HostScan(address="10.0.0.1")
    p = port(portid="80", protocol="tcp")
    scan.add_port(p)
    assert scan.has_ports() is True
    assert scan.ports["80/tcp"] is p


def test_hostscan_add_port_overwrites_duplicate(port):
    """A second port with the same portid/protocol replaces the first."""
    scan = HostScan(address="10.0.0.1")
    first = port(portid="80", protocol="tcp", product="nginx")
    second = port(portid="80", protocol="tcp", product="Apache")
    scan.add_port(first)
    scan.add_port(second)
    assert scan.ports["80/tcp"].product == "Apache"


def test_hostscan_distinct_protocols_coexist(port):
    """TCP/80 and UDP/80 are different port_keys and should both live in ports."""
    scan = HostScan(address="10.0.0.1")
    tcp = port(portid="80", protocol="tcp")
    udp = port(portid="80", protocol="udp")
    scan.add_port(tcp)
    scan.add_port(udp)
    assert set(scan.ports.keys()) == {"80/tcp", "80/udp"}
