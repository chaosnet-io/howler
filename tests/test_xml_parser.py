"""
Tests for scanner/xml_parser.py.

The parser converts nmap XML into PortInfo/HostScan dataclasses. Bugs here are
silent: a host that fails to parse simply doesn't get scanned, with no error
beyond a log line. These tests use crafted XML fixtures to pin:

- Basic port extraction (TCP and UDP)
- Merging TCP + UDP XML files for the same host
- SSL detection (tunnel attribute + port-based)
- CMS detection via http-devframework NSE script
- Filtering: hosts not in known_hosts, hosts with no open ports
- Robustness: malformed XML doesn't crash
"""
from __future__ import annotations

from pathlib import Path

import pytest

from scanner.xml_parser import parse_xml_files


# ── Fixtures ────────────────────────────────────────────────────────────────

_TCP_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap">
  <host>
    <address addrtype="ipv4" addr="10.10.10.5"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" tunnel="ssl"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http-proxy" product="Apache Tomcat"/>
        <script id="http-devframework" output="Tomcat"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="closed"/>
        <service name="mysql" product="MySQL"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_UDP_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap">
  <host>
    <address addrtype="ipv4" addr="10.10.10.5"/>
    <ports>
      <port protocol="udp" portid="161">
        <state state="open"/>
        <service name="snmp" product="net-snmp"/>
      </port>
      <port protocol="udp" portid="53">
        <state state="open"/>
        <service name="domain" product="ISC BIND"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_WORDPRESS_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap">
  <host>
    <address addrtype="ipv4" addr="10.10.10.10"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd"/>
        <script id="http-devframework" output="Wordpress"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_MALFORMED_XML = """\
<?xml version="1.0"?>
<nmaprun><host><address addrtype="ipv4" addr="10.10.10.99"
"""


@pytest.fixture
def xml_dir(tmp_path: Path) -> Path:
    """Empty dir; tests write specific XML files into it."""
    d = tmp_path / "xml"
    d.mkdir()
    return d


# ── Basic parsing ───────────────────────────────────────────────────────────

def test_parse_tcp_xml_extracts_open_ports(xml_dir):
    (xml_dir / "host.tcp.xml").write_text(_TCP_XML)
    scans = parse_xml_files(xml_dir, known_hosts={"10.10.10.5"})
    assert "10.10.10.5" in scans
    ports = scans["10.10.10.5"].ports
    # 4 open TCP ports (22, 80, 443, 8080); 3306 is closed → excluded
    assert set(ports.keys()) == {"22/tcp", "80/tcp", "443/tcp", "8080/tcp"}


def test_parse_closed_ports_excluded(xml_dir):
    (xml_dir / "host.tcp.xml").write_text(_TCP_XML)
    scans = parse_xml_files(xml_dir, known_hosts={"10.10.10.5"})
    assert "3306/tcp" not in scans["10.10.10.5"].ports


def test_parse_service_fields_populated(xml_dir):
    (xml_dir / "host.tcp.xml").write_text(_TCP_XML)
    scans = parse_xml_files(xml_dir, known_hosts={"10.10.10.5"})
    ssh = scans["10.10.10.5"].ports["22/tcp"]
    assert ssh.name == "ssh"
    assert ssh.product == "openssh"
    assert ssh.version == "8.9p1"
    assert ssh.protocol == "tcp"


# ── SSL detection ───────────────────────────────────────────────────────────

def test_parse_ssl_from_tunnel_attribute(xml_dir):
    (xml_dir / "host.tcp.xml").write_text(_TCP_XML)
    scans = parse_xml_files(xml_dir, known_hosts={"10.10.10.5"})
    https = scans["10.10.10.5"].ports["443/tcp"]
    assert https.ssl is True


def test_parse_ssl_from_port_443(xml_dir):
    """Port 443/tcp is always SSL even without tunnel attribute."""
    xml = """\
<?xml version="1.0"?>
<nmaprun><host>
  <address addrtype="ipv4" addr="10.0.0.1"/>
  <ports><port protocol="tcp" portid="443">
    <state state="open"/>
    <service name="https"/>
  </port></ports>
</host></nmaprun>
"""
    (xml_dir / "h.xml").write_text(xml)
    scans = parse_xml_files(xml_dir, known_hosts={"10.0.0.1"})
    assert scans["10.0.0.1"].ports["443/tcp"].ssl is True


def test_parse_ssl_from_port_8443(xml_dir):
    xml = """\
<?xml version="1.0"?>
<nmaprun><host>
  <address addrtype="ipv4" addr="10.0.0.1"/>
  <ports><port protocol="tcp" portid="8443">
    <state state="open"/>
    <service name="https-alt"/>
  </port></ports>
</host></nmaprun>
"""
    (xml_dir / "h.xml").write_text(xml)
    scans = parse_xml_files(xml_dir, known_hosts={"10.0.0.1"})
    assert scans["10.0.0.1"].ports["8443/tcp"].ssl is True


def test_parse_port_22_sets_ssl_true(xml_dir):
    """Historical quirk: parser sets ssl=True for port 22/tcp. This is kept for
    parity with the original nightcall (affects hydra -S flag in brute)."""
    (xml_dir / "host.tcp.xml").write_text(_TCP_XML)
    scans = parse_xml_files(xml_dir, known_hosts={"10.10.10.5"})
    assert scans["10.10.10.5"].ports["22/tcp"].ssl is True


# ── CMS detection ───────────────────────────────────────────────────────────

def test_parse_cms_wordpress(xml_dir):
    (xml_dir / "wp.xml").write_text(_WORDPRESS_XML)
    scans = parse_xml_files(xml_dir, known_hosts={"10.10.10.10"})
    assert scans["10.10.10.10"].ports["80/tcp"].cms == "Wordpress"


def test_parse_cms_tomcat_not_in_known_set(xml_dir):
    """Tomcat is detected by http-devframework but isn't in _KNOWN_CMS, so
    cms stays empty. The http module catches Tomcat via product instead."""
    (xml_dir / "host.tcp.xml").write_text(_TCP_XML)
    scans = parse_xml_files(xml_dir, known_hosts={"10.10.10.5"})
    # Tomcat's http-devframework output is "Tomcat" but only Wordpress/Django/Drupal/Joomla count
    assert scans["10.10.10.5"].ports["8080/tcp"].cms == ""


# ── TCP + UDP merge ─────────────────────────────────────────────────────────

def test_parse_merges_tcp_and_udp_files(xml_dir):
    """Two XML files for the same host (tcp + udp) should merge into one HostScan."""
    (xml_dir / "host.tcp.xml").write_text(_TCP_XML)
    (xml_dir / "host.udp.xml").write_text(_UDP_XML)
    scans = parse_xml_files(xml_dir, known_hosts={"10.10.10.5"})

    assert len(scans) == 1
    ports = scans["10.10.10.5"].ports
    # 4 TCP + 2 UDP = 6 ports total
    assert len(ports) == 6
    assert "22/tcp" in ports
    assert "161/udp" in ports
    assert "53/udp" in ports


# ── Filtering ───────────────────────────────────────────────────────────────

def test_parse_excludes_hosts_not_in_known(xml_dir):
    """If known_hosts is non-empty, hosts not in it are ignored."""
    (xml_dir / "host.tcp.xml").write_text(_TCP_XML)
    scans = parse_xml_files(xml_dir, known_hosts={"192.168.1.1"})
    assert scans == {}


def test_parse_empty_known_hosts_accepts_all(xml_dir):
    """Empty known_hosts means 'accept everything' (used in --skip-portscans)."""
    (xml_dir / "host.tcp.xml").write_text(_TCP_XML)
    scans = parse_xml_files(xml_dir, known_hosts=set())
    assert "10.10.10.5" in scans


def test_parse_ignores_masscan_xml(xml_dir):
    """masscan.xml is explicitly excluded even if it sits in xml/."""
    (xml_dir / "masscan.xml").write_text(_TCP_XML)
    (xml_dir / "host.tcp.xml").write_text(_TCP_XML)
    scans = parse_xml_files(xml_dir, known_hosts={"10.10.10.5"})
    # Should only parse host.tcp.xml once (not masscan.xml)
    assert len(scans["10.10.10.5"].ports) == 4


def test_parse_host_with_no_open_ports_filtered(xml_dir):
    xml = """\
<?xml version="1.0"?>
<nmaprun><host>
  <address addrtype="ipv4" addr="10.0.0.1"/>
  <ports><port protocol="tcp" portid="80">
    <state state="closed"/>
    <service name="http"/>
  </port></ports>
</host></nmaprun>
"""
    (xml_dir / "h.xml").write_text(xml)
    scans = parse_xml_files(xml_dir, known_hosts={"10.0.0.1"})
    # No open ports → host filtered out entirely
    assert "10.0.0.1" not in scans


# ── Robustness ──────────────────────────────────────────────────────────────

def test_parse_malformed_xml_does_not_crash(xml_dir):
    """Malformed XML should be caught by the except and return empty, not raise."""
    (xml_dir / "broken.xml").write_text(_MALFORMED_XML)
    # Should not raise
    scans = parse_xml_files(xml_dir, known_hosts={"10.10.10.99"})
    assert scans == {}


def test_parse_empty_directory_returns_empty(tmp_path):
    d = tmp_path / "empty_xml"
    d.mkdir()
    assert parse_xml_files(d, known_hosts=set()) == {}
