"""
Tests for the 11 service modules + BruteModule.

Each module gets:
- parametrized match() tests (True for ports the module claims, False for others)
- jobs() tests covering argv construction, tool-missing behaviour, and the
  feature flags (--brute, --web) that gate execution

These tests never invoke the underlying tools — they verify that the right
argv is built for the right port. A regression here is exactly the "silent
under-coverage" failure mode the suite exists to catch.
"""
from __future__ import annotations

import pytest

from modules.brute import BruteModule
from modules.dns import DnsModule
from modules.http import HttpModule
from modules.ike import IkeModule
from modules.ipmi import IpmiModule
from modules.nfs import NfsModule
from modules.rmi import RmiModule
from modules.smb import SmbModule
from modules.smtp import SmtpModule
from modules.snmp import SnmpModule
from modules.ssh import SshModule
from modules.ssl_tls import SslTlsModule


HOST = "10.10.10.5"


# ═══════════════════════════════════════════════════════════════════════════
# match() — parametrized True/False cases per module
# ═══════════════════════════════════════════════════════════════════════════

# (module_factory, portid, protocol, name, product, ssl, expected)
_MATCH_CASES = [
    # SslTlsModule — matches on ssl flag only
    (SslTlsModule, "443", "tcp", "https", "", True, True),
    (SslTlsModule, "8443", "tcp", "https-alt", "", True, True),
    (SslTlsModule, "80", "tcp", "http", "", False, False),
    (SslTlsModule, "22", "tcp", "ssh", "", False, False),

    # HttpModule — delegates to PortInfo.is_http
    (HttpModule, "80", "tcp", "http", "", False, True),
    (HttpModule, "443", "tcp", "https", "", False, True),
    (HttpModule, "8080", "tcp", "http-proxy", "", False, True),
    (HttpModule, "12345", "tcp", "http", "Apache httpd", False, True),
    (HttpModule, "22", "tcp", "ssh", "OpenSSH", False, False),
    (HttpModule, "80", "tcp", "http", "httpapi", False, False),

    # DnsModule
    (DnsModule, "53", "tcp", "domain", "", False, True),
    (DnsModule, "53", "udp", "domain", "", False, True),
    (DnsModule, "80", "tcp", "http", "", False, False),

    # SshModule
    (SshModule, "22", "tcp", "ssh", "", False, True),
    (SshModule, "2222", "tcp", "ssh", "", False, True),
    (SshModule, "80", "tcp", "http", "", False, False),

    # SmbModule — TCP 139/445 only
    (SmbModule, "139", "tcp", "netbios-ssn", "", False, True),
    (SmbModule, "445", "tcp", "microsoft-ds", "", False, True),
    (SmbModule, "139", "udp", "netbios-ssn", "", False, False),
    (SmbModule, "80", "tcp", "http", "", False, False),

    # SmtpModule
    (SmtpModule, "25", "tcp", "smtp", "", False, True),
    (SmtpModule, "465", "tcp", "smtps", "", False, True),
    (SmtpModule, "587", "tcp", "submission", "", False, True),
    (SmtpModule, "80", "tcp", "http", "", False, False),

    # SnmpModule
    (SnmpModule, "161", "udp", "snmp", "", False, True),
    (SnmpModule, "161", "tcp", "snmp", "", False, True),
    (SnmpModule, "80", "tcp", "http", "", False, False),

    # NfsModule
    (NfsModule, "2049", "tcp", "nfs", "", False, True),
    (NfsModule, "2049", "udp", "nfs", "", False, True),
    (NfsModule, "80", "tcp", "http", "", False, False),

    # IkeModule — name or port 500/4500
    (IkeModule, "500", "udp", "isakmp", "", False, True),
    (IkeModule, "4500", "udp", "nat-t-ike", "", False, True),
    (IkeModule, "80", "tcp", "http", "", False, False),

    # IpmiModule
    (IpmiModule, "623", "udp", "rmcp", "", False, True),
    (IpmiModule, "49152", "tcp", "http", "", False, True),
    (IpmiModule, "80", "tcp", "http", "", False, False),

    # RmiModule
    (RmiModule, "1099", "tcp", "java-rmi", "", False, True),
    (RmiModule, "1099", "tcp", "rmi", "", False, True),
    (RmiModule, "80", "tcp", "http", "", False, False),
]


@pytest.mark.parametrize(
    "module_cls,portid,protocol,name,product,ssl,expected",
    _MATCH_CASES,
    ids=[f"{c[0].__name__}-{c[1]}/{c[2]}" for c in _MATCH_CASES],
)
def test_module_match(port, module_cls, portid, protocol, name, product, ssl, expected):
    p = port(portid=portid, protocol=protocol, name=name, product=product, ssl=ssl)
    assert module_cls().match(p) is expected


# ═══════════════════════════════════════════════════════════════════════════
# jobs() — argv construction per module
# ═══════════════════════════════════════════════════════════════════════════

# ── SslTlsModule ────────────────────────────────────────────────────────────

def test_ssl_tls_jobs_builds_testssl_cmd(config, port):
    p = port(portid="443", ssl=True)
    jobs = SslTlsModule().jobs(HOST, p, config)
    assert len(jobs) == 1
    job = jobs[0]
    assert job.cmd[0] == "/fake/testssl.sh"
    assert "--color" in job.cmd and "0" in job.cmd
    assert "--quiet" in job.cmd
    assert f"{HOST}:443" in job.cmd
    assert job.category == "misc"
    assert job.host == HOST
    assert "443.misc.ssl" in job.output_file


def test_ssl_tls_jobs_no_tool_returns_empty(config, port):
    config.tool_paths.pop("testssl.sh")
    p = port(portid="443", ssl=True)
    assert SslTlsModule().jobs(HOST, p, config) == []


# ── HttpModule ──────────────────────────────────────────────────────────────
# Note: http.py checks tool availability via config.tool() but builds cmd with
# bare tool names (e.g. "whatweb") rather than resolved paths. The MSF jobs
# (tomcat/jboss) are the exception — they use config.tool("msfconsole").
# These tests pin that current behaviour.


def test_http_jobs_baseline_whatweb_wafw00f_gowitness(config, port):
    """Without --web, only whatweb + wafw00f + gowitness fire."""
    p = port(portid="80", name="http")
    jobs = HttpModule().jobs(HOST, p, config)
    tools = [j.cmd[0] for j in jobs]
    assert "whatweb" in tools
    assert "wafw00f" in tools
    assert "gowitness" in tools
    # --web gated tools absent
    assert "ffuf" not in tools
    assert "nikto" not in tools
    assert all(j.host == HOST for j in jobs)
    assert all(j.category == "http" for j in jobs)


def test_http_jobs_baseline_uses_scheme(config, port):
    p = port(portid="443", ssl=True)
    jobs = HttpModule().jobs(HOST, p, config)
    whatweb = next(j for j in jobs if "whatweb" in j.description)
    assert "https://10.10.10.5:443" in whatweb.cmd[-1]


def test_http_jobs_web_flag_adds_ffuf_nikto(config, port):
    config.enable_web = True
    p = port(portid="80", name="http")
    jobs = HttpModule().jobs(HOST, p, config)
    tools = [j.cmd[0] for j in jobs]
    assert "ffuf" in tools
    assert "nikto" in tools


def test_http_jobs_wordlist_missing_skips_ffuf(config, port, tmp_path):
    """If the wordlist can't be resolved and no SecLists install is found,
    ffuf must be skipped loudly (not produce a doomed job that fails at runtime)."""
    config.enable_web = True
    config.http_fuzz_small = tmp_path / "nonexistent.txt"
    config.http_fuzz_large = tmp_path / "nonexistent.txt"
    p = port(portid="80", name="http")
    jobs = HttpModule().jobs(HOST, p, config)
    tools = [j.cmd[0] for j in jobs]
    assert "ffuf" not in tools
    # Other --web tools still fire
    assert "nikto" in tools


def test_http_jobs_wordpress_cms_triggers_wpscan(config, port):
    config.enable_web = True
    p = port(portid="80", name="http", cms="Wordpress")
    jobs = HttpModule().jobs(HOST, p, config)
    assert any("wpscan" in j.description for j in jobs)


def test_http_jobs_joomla_cms_triggers_joomscan(config, port):
    config.enable_web = True
    p = port(portid="80", name="http", cms="Joomla")
    jobs = HttpModule().jobs(HOST, p, config)
    assert any("joomscan" in j.description for j in jobs)


def test_http_jobs_tomcat_triggers_msf(config, port):
    """Tomcat/JBoss product → MSF tomcat_mgr_login + jboss_vulnscan.

    Note: the http module checks ``"tomcat" in port.product`` (case-sensitive),
    so this relies on the XML parser lowercasing the product field. We pass
    lowercase here to match real PortInfo instances produced by the parser.
    """
    config.enable_web = True
    p = port(portid="8080", name="http", product="apache tomcat")
    jobs = HttpModule().jobs(HOST, p, config)
    msf_jobs = [j for j in jobs if j.category == "msf"]
    assert len(msf_jobs) == 2  # tomcat_mgr_login + jboss_vulnscan
    assert all(j.cmd[0] == "/fake/msfconsole" for j in msf_jobs)


def test_http_jobs_individual_tool_missing_skipped(config, port):
    """If whatweb is missing, the other http jobs still fire."""
    config.tool_paths.pop("whatweb")
    p = port(portid="80", name="http")
    jobs = HttpModule().jobs(HOST, p, config)
    tools = [j.cmd[0] for j in jobs]
    assert "wafw00f" in tools
    assert "gowitness" in tools
    assert "whatweb" not in tools


# ── DnsModule ───────────────────────────────────────────────────────────────

def test_dns_jobs_tcp(monkeypatch, config, port):
    monkeypatch.setattr("modules.dns._resolve_domain", lambda h, tcp: "example.com")
    p = port(portid="53", protocol="tcp", name="domain")
    jobs = DnsModule().jobs(HOST, p, config)
    # 2 jobs: reverse + forward
    assert len(jobs) == 2
    assert all(j.cmd[0] == "/fake/dnsrecon" for j in jobs)
    assert all("--tcp" in j.cmd for j in jobs)
    assert all(j.category == "misc" for j in jobs)


def test_dns_jobs_udp_no_tcp_flag(monkeypatch, config, port):
    monkeypatch.setattr("modules.dns._resolve_domain", lambda h, tcp: "example.com")
    p = port(portid="53", protocol="udp", name="domain")
    jobs = DnsModule().jobs(HOST, p, config)
    assert len(jobs) == 2
    assert all("--tcp" not in j.cmd for j in jobs)


def test_dns_jobs_no_forward_when_ptr_fails(monkeypatch, config, port):
    """If _resolve_domain returns None (no PTR), only the reverse job fires."""
    monkeypatch.setattr("modules.dns._resolve_domain", lambda h, tcp: None)
    p = port(portid="53", protocol="tcp", name="domain")
    jobs = DnsModule().jobs(HOST, p, config)
    assert len(jobs) == 1


def test_dns_jobs_no_tool_returns_empty(config, port):
    config.tool_paths.pop("dnsrecon")
    p = port(portid="53", name="domain")
    assert DnsModule().jobs(HOST, p, config) == []


# ── SshModule ───────────────────────────────────────────────────────────────

def test_ssh_jobs_builds_ssh_audit_cmd(config, port):
    p = port(portid="22", name="ssh")
    jobs = SshModule().jobs(HOST, p, config)
    assert len(jobs) == 1
    job = jobs[0]
    assert job.cmd[0] == "/fake/ssh-audit"
    assert "-p" in job.cmd and "22" in job.cmd
    assert HOST in job.cmd
    assert job.category == "misc"
    assert "ssh_audit" in job.output_file


def test_ssh_jobs_no_tool_returns_empty(config, port):
    config.tool_paths.pop("ssh-audit")
    p = port(portid="22", name="ssh")
    assert SshModule().jobs(HOST, p, config) == []


# ── SmbModule ───────────────────────────────────────────────────────────────

def test_smb_jobs_builds_enum4linux_cmd(config, port):
    p = port(portid="445", protocol="tcp", name="microsoft-ds")
    jobs = SmbModule().jobs(HOST, p, config)
    assert len(jobs) == 1
    job = jobs[0]
    assert job.cmd[0] == "/fake/enum4linux-ng"
    assert "-A" in job.cmd
    assert HOST in job.cmd
    assert "-oA" in job.cmd
    assert job.category == "misc"


def test_smb_jobs_no_tool_returns_empty(config, port):
    config.tool_paths.pop("enum4linux-ng")
    p = port(portid="445", protocol="tcp")
    assert SmbModule().jobs(HOST, p, config) == []


# ── SmtpModule ──────────────────────────────────────────────────────────────

def test_smtp_jobs_builds_smtp_user_enum_cmd(config, port):
    p = port(portid="25", name="smtp")
    jobs = SmtpModule().jobs(HOST, p, config)
    assert len(jobs) == 1
    job = jobs[0]
    assert job.cmd[0] == "/fake/smtp-user-enum"
    assert "-M" in job.cmd and "RCPT" in job.cmd
    assert "-t" in job.cmd and HOST in job.cmd
    assert job.category == "misc"


def test_smtp_jobs_user_dict_missing_returns_empty(config, port, tmp_path):
    config.user_dict = tmp_path / "nonexistent.txt"
    p = port(portid="25", name="smtp")
    assert SmtpModule().jobs(HOST, p, config) == []


def test_smtp_jobs_no_tool_returns_empty(config, port):
    config.tool_paths.pop("smtp-user-enum")
    p = port(portid="25", name="smtp")
    assert SmtpModule().jobs(HOST, p, config) == []


# ── SnmpModule ──────────────────────────────────────────────────────────────

def test_snmp_jobs_builds_msf_cmd(config, port):
    p = port(portid="161", protocol="udp", name="snmp")
    jobs = SnmpModule().jobs(HOST, p, config)
    assert len(jobs) == 1
    job = jobs[0]
    assert job.cmd[0] == "/fake/msfconsole"
    # MSF argv layout: [msf, "-q", "-x", "<command string>", "-o", "<outfile>"]
    msf_cmd = job.cmd[3]
    assert "snmp_login" in msf_cmd
    assert f"RHOSTS {HOST}" in msf_cmd
    assert job.category == "msf"


def test_snmp_jobs_snmp_dict_missing_returns_empty(config, port, tmp_path):
    config.snmp_dict = tmp_path / "nonexistent.txt"
    p = port(portid="161", name="snmp")
    assert SnmpModule().jobs(HOST, p, config) == []


def test_snmp_jobs_no_tool_returns_empty(config, port):
    config.tool_paths.pop("msfconsole")
    p = port(portid="161", name="snmp")
    assert SnmpModule().jobs(HOST, p, config) == []


# ── NfsModule ───────────────────────────────────────────────────────────────

def test_nfs_jobs_builds_showmount_cmd(config, port):
    p = port(portid="2049", name="nfs")
    jobs = NfsModule().jobs(HOST, p, config)
    assert len(jobs) == 1
    job = jobs[0]
    assert job.cmd[0] == "/fake/showmount"
    assert "-e" in job.cmd
    assert HOST in job.cmd
    assert "misc.nfs" in job.output_file


def test_nfs_jobs_no_tool_returns_empty(config, port):
    config.tool_paths.pop("showmount")
    p = port(portid="2049", name="nfs")
    assert NfsModule().jobs(HOST, p, config) == []


# ── IkeModule ───────────────────────────────────────────────────────────────

def test_ike_jobs_port_500_two_variants(config, port):
    """Plain IKE (port 500) → IKEv1 + IKEv2 jobs."""
    p = port(portid="500", protocol="udp", name="isakmp")
    jobs = IkeModule().jobs(HOST, p, config)
    assert len(jobs) == 2
    assert any("IKEv1" in j.description for j in jobs)
    assert any("IKEv2" in j.description for j in jobs)
    assert all(j.cmd[0] == "/fake/ike-scan" for j in jobs)
    assert all("misc.ike" in j.output_file for j in jobs)


def test_ike_jobs_nat_t_two_variants(config, port):
    """NAT-T (port 4500 or name 'nat-t-ike') → NAT-T IKEv1 + IKEv2."""
    p = port(portid="4500", protocol="udp", name="nat-t-ike")
    jobs = IkeModule().jobs(HOST, p, config)
    assert len(jobs) == 2
    assert all("--nat-t" in j.cmd for j in jobs)
    assert all("misc.nat-ike" in j.output_file for j in jobs)


def test_ike_jobs_no_tool_returns_empty(config, port):
    config.tool_paths.pop("ike-scan")
    p = port(portid="500", name="isakmp")
    assert IkeModule().jobs(HOST, p, config) == []


# ── IpmiModule ──────────────────────────────────────────────────────────────

def test_ipmi_jobs_port_623_three_modules(config, port):
    """Port 623 fires all three IPMI scanners."""
    p = port(portid="623", protocol="udp", name="rmcp")
    jobs = IpmiModule().jobs(HOST, p, config)
    assert len(jobs) == 3
    descs = " ".join(j.description for j in jobs)
    assert "ipmi_version" in descs
    assert "ipmi_dumphashes" in descs
    assert "ipmi_cipher_zero" in descs
    assert all(j.cmd[0] == "/fake/msfconsole" for j in jobs)
    assert all(j.category == "msf" for j in jobs)


def test_ipmi_jobs_port_49152_smt_only(config, port):
    """Port 49152 fires only the SMT IPMI exposure check."""
    p = port(portid="49152", protocol="tcp", name="http")
    jobs = IpmiModule().jobs(HOST, p, config)
    assert len(jobs) == 1
    assert "smt_ipmi_49152_exposure" in jobs[0].description


def test_ipmi_jobs_no_tool_returns_empty(config, port):
    config.tool_paths.pop("msfconsole")
    p = port(portid="623", name="rmcp")
    assert IpmiModule().jobs(HOST, p, config) == []


# ── RmiModule ───────────────────────────────────────────────────────────────

def test_rmi_jobs_builds_msf_cmd(config, port):
    p = port(portid="1099", name="java-rmi")
    jobs = RmiModule().jobs(HOST, p, config)
    assert len(jobs) == 1
    job = jobs[0]
    assert job.cmd[0] == "/fake/msfconsole"
    assert "java_rmi_server" in job.cmd[3]
    assert job.category == "msf"


def test_rmi_jobs_no_tool_returns_empty(config, port):
    config.tool_paths.pop("msfconsole")
    p = port(portid="1099", name="java-rmi")
    assert RmiModule().jobs(HOST, p, config) == []


# ═══════════════════════════════════════════════════════════════════════════
# BruteModule — flag-gated, the most conditional logic
# ═══════════════════════════════════════════════════════════════════════════

def test_brute_jobs_disabled_when_flag_off(config, port):
    """The --brute flag gates everything — even matching ports yield no jobs."""
    config.enable_brute = False
    p = port(portid="22", name="ssh")
    assert BruteModule().jobs(HOST, p, config) == []


def test_brute_jobs_ssh_triggers_hydra(config, port):
    config.enable_brute = True
    p = port(portid="22", name="ssh", ssl=False)
    jobs = BruteModule().jobs(HOST, p, config)
    assert len(jobs) == 1
    job = jobs[0]
    assert job.cmd[0] == "/fake/hydra"
    assert "-L" in job.cmd  # user list
    assert "-P" in job.cmd  # pass list
    assert "-e" in job.cmd and "ns" in job.cmd  # empty password + same as login
    assert "ssh" in job.cmd  # protocol
    assert job.category == "brute"
    assert "22.brute" in job.output_file or "ssh.brute" in job.output_file


def test_brute_jobs_ssl_adds_dash_S(config, port):
    config.enable_brute = True
    p = port(portid="465", name="smtp", ssl=True)
    jobs = BruteModule().jobs(HOST, p, config)
    assert "-S" in jobs[0].cmd


def test_brute_jobs_tftp_uses_msf(config, port):
    config.enable_brute = True
    p = port(portid="69", protocol="udp", name="tftp")
    jobs = BruteModule().jobs(HOST, p, config)
    assert len(jobs) == 1
    assert jobs[0].cmd[0] == "/fake/msfconsole"
    assert "tftpbrute" in jobs[0].cmd[3]


def test_brute_jobs_hydra_missing_returns_empty(config, port):
    config.enable_brute = True
    config.tool_paths.pop("hydra")
    p = port(portid="22", name="ssh")
    assert BruteModule().jobs(HOST, p, config) == []


def test_brute_jobs_user_dict_missing_returns_empty(config, port, tmp_path):
    config.enable_brute = True
    config.user_dict = tmp_path / "nonexistent.txt"
    p = port(portid="22", name="ssh")
    assert BruteModule().jobs(HOST, p, config) == []


def test_brute_jobs_non_brute_protocol_returns_empty(config, port):
    """Ports that aren't in _HYDRA_PROTOCOLS and aren't TFTP yield no jobs."""
    config.enable_brute = True
    p = port(portid="80", name="http")
    assert BruteModule().jobs(HOST, p, config) == []


@pytest.mark.parametrize("proto", ["ftp", "mssql", "mysql", "rexec", "rlogin", "rsh", "smtp", "ssh", "telnet", "vnc"])
def test_brute_match_all_hydra_protocols(port, proto):
    """Every protocol in _HYDRA_PROTOCOLS should match BruteModule."""
    p = port(portid="1", name=proto)
    assert BruteModule().match(p) is True


def test_brute_match_tftp_port(port):
    assert BruteModule().match(port(portid="69", name="tftp")) is True


def test_brute_match_non_brute_port(port):
    assert BruteModule().match(port(portid="80", name="http")) is False


def test_brute_match_returns_true_even_when_disabled(port):
    """Known wart: match() returns True regardless of enable_brute (the
    _config_brute_enabled class attr is dead code). jobs() is the real gate.

    Pinning this so a future cleanup doesn't silently change dispatch behaviour.
    If someone fixes the wart (makes match() respect the flag), this test will
    fail and force them to update the registry dispatch contract too.
    """
    p = port(portid="22", name="ssh")
    assert BruteModule().match(p) is True
