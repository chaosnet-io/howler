"""
Nmap XML output parser.
Converts nmap XML files into HostScan/PortInfo dataclass structures.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as etree
from pathlib import Path

from models import HostScan, PortInfo

log = logging.getLogger(__name__)

# CMS frameworks detected via http-devframework NSE script
_KNOWN_CMS = {"Wordpress", "Django", "Drupal", "Joomla"}

# Ports that imply SSL when combined with TCP
_SSL_PORTS = {"443", "8443"}

# Ports that imply SSL regardless of service tunnel attribute
_ALWAYS_SSL_TCP_PORTS = {"443", "8443"}


def parse_xml_files(xml_dir: Path, known_hosts: set[str]) -> dict[str, HostScan]:
    """
    Parse all nmap XML files in xml_dir (excluding masscan.xml).
    Only populates entries for IPs in known_hosts.
    Returns dict keyed by IP address, with only hosts that have open ports.
    """
    scans: dict[str, HostScan] = {}

    xml_files = [
        f for f in xml_dir.glob("*.xml")
        if f.name != "masscan.xml"
    ]
    log.info(f"Importing port data from {len(xml_files)} file(s)")

    for xml_file in xml_files:
        partial = _parse_single_xml(xml_file, known_hosts)
        for addr, host_scan in partial.items():
            if addr in scans:
                # Merge ports from multiple XML files (e.g. tcp + udp)
                for key, port in host_scan.ports.items():
                    scans[addr].ports[key] = port
            else:
                scans[addr] = host_scan

    # Remove hosts with no open ports
    return {addr: scan for addr, scan in scans.items() if scan.has_ports()}


def _parse_single_xml(path: Path, known_hosts: set[str]) -> dict[str, HostScan]:
    scans: dict[str, HostScan] = {}
    try:
        root = etree.parse(path).getroot()
        for host_elem in root.iter(tag="host"):
            addr = _extract_ipv4(host_elem)
            if not addr or (known_hosts and addr not in known_hosts):
                continue

            if addr not in scans:
                scans[addr] = HostScan(address=addr)

            for port_elem in host_elem.iter(tag="port"):
                port = _extract_port(port_elem)
                if port is not None:
                    scans[addr].add_port(port)

    except Exception as e:
        log.error(f"Error parsing {path}: {e}")

    return scans


def _extract_ipv4(host_elem) -> str | None:
    for address in host_elem.iter(tag="address"):
        if address.attrib.get("addrtype") == "ipv4":
            return address.attrib.get("addr")
    return None


def _extract_port(port_elem) -> PortInfo | None:
    state = port_elem.find("state")
    if state is None or state.attrib.get("state", "").lower() != "open":
        return None

    portid = port_elem.attrib.get("portid", "")
    protocol = port_elem.attrib.get("protocol", "tcp")

    name = product = version = cms = ""
    ssl = _detect_ssl_from_port(portid, protocol, port_elem)

    service = port_elem.find("service")
    if service is not None:
        name = service.attrib.get("name", "").lower()
        product = service.attrib.get("product", "").lower()
        version = service.attrib.get("version", "")
        if "tunnel" in service.attrib:
            ssl = True

    cms = _detect_cms(port_elem)

    return PortInfo(
        portid=portid,
        protocol=protocol,
        name=name,
        product=product,
        version=version,
        ssl=ssl,
        cms=cms,
    )


def _detect_ssl_from_port(portid: str, protocol: str, port_elem) -> bool:
    if protocol == "tcp" and portid in _ALWAYS_SSL_TCP_PORTS:
        return True
    # Also check port 22 (SSH is not SSL, but original script set ssl=True for it;
    # keeping that behaviour since it affects auth brute SSL flag in the original)
    if protocol == "tcp" and portid == "22":
        return True
    return False


def _detect_cms(port_elem) -> str:
    for script in port_elem.iter(tag="script"):
        if "http-devframework" in script.attrib.get("id", ""):
            output = script.attrib.get("output", "")
            fwk = output.split()[0] if output.split() else ""
            if fwk in _KNOWN_CMS:
                return fwk
    return ""
