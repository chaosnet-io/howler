"""
Address-family helpers for Howler.

Pure, stdlib-only utilities used across the pipeline and the modules so IPv4 and
IPv6 targets are handled uniformly. The primitive is family detection via
``ipaddress.ip_network(strict=False).version``, which accepts both bare addresses
(``"2001:db8::1"``) and CIDR blocks (``"2001:db8::/120"``).
"""

from __future__ import annotations

import ipaddress

# IPv6 prefixes shorter than this (i.e. more than 256 hosts) are not expanded
# into individual host entries by expand_cidrs(): a /64 is 2**64 addresses and
# would OOM. /120 == 256 hosts.
MAX_IPV6_EXPAND_PREFIX = 120


def _version(target: str) -> int:
    """Return the IP version (4 or 6) of an address or CIDR string."""
    return ipaddress.ip_network(target, strict=False).version


def is_ipv4(target: str) -> bool:
    return _version(target) == 4


def is_ipv6(target: str) -> bool:
    return _version(target) == 6


def bracket(host: str) -> str:
    """Wrap IPv6 literals in square brackets for URL / host:port contexts."""
    return f"[{host}]" if is_ipv6(host) else host


def hostport(host: str, port: str) -> str:
    """Format ``host:port``, bracketing IPv6 literals."""
    return f"{bracket(host)}:{port}"


def safe_filename(host: str) -> str:
    """Filesystem-safe host string for output filenames.

    IPv4 addresses are returned unchanged (so existing output naming and tests
    are unaffected); IPv6 colons become underscores.
    """
    return host.replace(":", "_") if is_ipv6(host) else host


def split_by_family(targets: list[str]) -> tuple[list[str], list[str]]:
    """Split a mixed target list (addresses and/or CIDRs) into IPv4/IPv6 lists."""
    ipv4: list[str] = []
    ipv6: list[str] = []
    for target in targets:
        (ipv6 if is_ipv6(target) else ipv4).append(target)
    return ipv4, ipv6
