"""
Tests for the ModuleRegistry and build_default_registry().

The key contract: unlike nightcall's first-match if/elif chain, ALL matching
modules fire per port. This is the behaviour that lets an HTTPS port get both
testssl.sh (ssl_tls) and whatweb/ffuf/nikto (http) simultaneously. A regression
here would silently drop entire scan categories.
"""
from __future__ import annotations

from modules import ModuleRegistry, build_default_registry
from modules.dns import DnsModule
from modules.http import HttpModule
from modules.smb import SmbModule
from modules.ssl_tls import SslTlsModule


HOST = "10.10.10.5"


# ── Registry mechanics ──────────────────────────────────────────────────────

def test_registry_starts_empty():
    reg = ModuleRegistry()
    assert reg.all_modules() == []


def test_registry_register_returns_all():
    reg = ModuleRegistry()
    ssl = SslTlsModule()
    http = HttpModule()
    reg.register(ssl)
    reg.register(http)
    assert reg.all_modules() == [ssl, http]


def test_registry_all_modules_returns_copy():
    """all_modules() returns a copy so external mutation doesn't affect state."""
    reg = ModuleRegistry()
    reg.register(SslTlsModule())
    mods = reg.all_modules()
    mods.clear()
    assert len(reg.all_modules()) == 1


# ── All-matches-fire semantics ──────────────────────────────────────────────

def test_dispatch_https_port_fires_both_ssl_and_http(config, port):
    """The headline contract: HTTPS → ssl_tls + http jobs, not first-match."""
    reg = ModuleRegistry()
    reg.register(SslTlsModule())
    reg.register(HttpModule())

    p = port(portid="443", name="https", ssl=True)
    jobs = reg.dispatch(HOST, p, config)

    categories = {j.category for j in jobs}
    assert "misc" in categories   # ssl_tls → testssl.sh
    assert "http" in categories   # http → whatweb/wafw00f/gowitness


def test_dispatch_non_ssl_http_fires_only_http(config, port):
    reg = ModuleRegistry()
    reg.register(SslTlsModule())
    reg.register(HttpModule())

    p = port(portid="80", name="http", ssl=False)
    jobs = reg.dispatch(HOST, p, config)
    categories = {j.category for j in jobs}
    assert categories == {"http"}


def test_dispatch_unknown_port_fires_nothing(config, port):
    reg = ModuleRegistry()
    reg.register(SslTlsModule())
    reg.register(HttpModule())
    reg.register(DnsModule())

    p = port(portid="9999", name="unknown", product="")
    assert reg.dispatch(HOST, p, config) == []


def test_dispatch_aggregates_across_many_modules(config, port):
    """A port could theoretically match several modules — all should fire."""
    reg = ModuleRegistry()
    for mod_cls in (SslTlsModule, HttpModule, DnsModule, SmbModule):
        reg.register(mod_cls())
    # Port 445 is microsoft-ds over TCP; only SmbModule should match
    p = port(portid="445", protocol="tcp", name="microsoft-ds")
    jobs = reg.dispatch(HOST, p, config)
    assert len(jobs) >= 1
    assert all(j.host == HOST for j in jobs)


# ── Default registry ────────────────────────────────────────────────────────

def test_build_default_registry_includes_all_protocols():
    """The default registry should have a module for every protocol the
    config.yaml advertises scanning: ssl, http, dns, ssh, smb, smtp, snmp,
    nfs, ike, ipmi. RMI is handled by nmap NSE rmi-vuln-classloader directly
    (no module needed)."""
    reg = build_default_registry()
    names = {type(m).__name__ for m in reg.all_modules()}
    expected = {
        "SslTlsModule", "HttpModule", "DnsModule", "SshModule", "SmbModule",
        "SmtpModule", "SnmpModule", "NfsModule", "IkeModule", "IpmiModule",
    }
    assert expected == names


def test_build_default_registry_ssl_registered_first():
    """SslTlsModule is registered first so testssl.sh runs early on HTTPS ports.
    Pin the ordering — the comment in modules/__init__.py documents the intent."""
    reg = build_default_registry()
    assert isinstance(reg.all_modules()[0], SslTlsModule)
