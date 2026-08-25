"""
HTTP/HTTPS module.
Tools: wafw00f, whatweb, ffuf (replaces wfuzz), nikto, gowitness (replaces cutycapt+xvfb),
       wpscan, joomscan.
Tomcat manager login brute uses hydra http-get against /manager/html (no msfconsole).
"""

from __future__ import annotations

import logging

import netutil
from config import Config
from models import Job, PortInfo
from modules import BaseModule

log = logging.getLogger(__name__)


class HttpModule(BaseModule):
    required_tools = ["whatweb", "wafw00f", "ffuf", "nikto", "gowitness", "wpscan", "joomscan", "hydra"]

    def match(self, port: PortInfo) -> bool:
        return port.is_http

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        jobs: list[Job] = []
        scheme = port.scheme
        base = f"{scheme}://{netutil.bracket(host)}:{port.portid}"

        # Always-on: whatweb, wafw00f, gowitness screenshot
        if config.tool("whatweb"):
            jobs.append(Job(
                cmd=["whatweb", "-vv", base],
                output_file=f"{netutil.safe_filename(host)}-{port.portid}.{scheme}.whatweb",
                category="http",
                host=host,
                description=f"whatweb {base}",
            ))

        if config.tool("wafw00f"):
            jobs.append(Job(
                cmd=["wafw00f", "-v", base],
                output_file=f"{netutil.safe_filename(host)}-{port.portid}.{scheme}.waf",
                category="http",
                host=host,
                description=f"wafw00f {base}",
            ))

        if config.tool("gowitness"):
            # gowitness v3 CLI: `scan single --url`. Screenshots are auto-named
            # into --screenshot-path (no per-file --destination anymore), so we
            # leave output_file empty and let the organizer sweep *.png into
            # http/images. --write-none disables the metadata DB/CSV writers.
            jobs.append(Job(
                cmd=[
                    "gowitness", "scan", "single",
                    "--url", base,
                    "--screenshot-path", ".",
                    "--screenshot-format", "png",
                    "--write-none",
                ],
                output_file="",
                category="http",
                host=host,
                description=f"gowitness {base}",
            ))

        # --web flag extras
        if config.enable_web:
            fuzz_list = str(
                config.http_fuzz_large if not config.large_test else config.http_fuzz_small
            )

            if config.tool("ffuf"):
                # ffuf aborts with a usage dump if the wordlist can't be read.
                # Auto-detect the SecLists install (the default paths don't exist
                # on every distro, e.g. NixOS); skip loudly if nothing is found
                # rather than launching a doomed job.
                wordlist = config.resolve_wordlist(fuzz_list)
                if wordlist:
                    jobs.append(Job(
                        cmd=[
                            "ffuf",
                            "-w", str(wordlist),
                            "-u", f"{base}/FUZZ",
                            "-o", f"{netutil.safe_filename(host)}-{port.portid}.{scheme}.ffuf",
                            "-of", "json",
                            "-fc", "302,400,401,403,404",
                            "-r",
                            "-recursion", "-recursion-depth", "2",
                            "-s",
                        ],
                        output_file=f"{netutil.safe_filename(host)}-{port.portid}.{scheme}.ffuf",
                        category="http",
                        host=host,
                        description=f"ffuf {base}",
                    ))
                else:
                    log.warning(
                        f"ffuf wordlist not found ({fuzz_list}) and no SecLists "
                        f"install auto-detected — skipping web fuzzing for {base}. "
                        f"Set wordlists.http_fuzz_small / http_fuzz_large in "
                        f"config.yaml, or export HOWLER_SECLISTS=/path/to/seclists."
                    )

            if config.tool("nikto"):
                ssl_flag = ["-ssl"] if port.ssl else []
                jobs.append(Job(
                    cmd=[
                        "nikto",
                        "-nolookup", "-nointeractive",
                        "-timeout", "5",
                        "-evasion", "1",
                        *ssl_flag,
                        "-h", netutil.hostport(host, port.portid),
                    ],
                    output_file=f"{netutil.safe_filename(host)}-{port.portid}.{scheme}.nikto",
                    category="http",
                    host=host,
                    description=f"nikto {base}",
                ))

            # CMS-specific scanners
            cms = port.cms.lower()
            if "wordpress" in cms and config.tool("wpscan"):
                jobs.append(Job(
                    cmd=[
                        "wpscan",
                        "-u", base,
                        "--follow-redirection",
                        "--batch",
                        "--no-color",
                    ],
                    output_file=f"{netutil.safe_filename(host)}-{port.portid}.{scheme}.wpscan",
                    category="http",
                    host=host,
                    description=f"wpscan {base}",
                ))
            elif "joomla" in cms and config.tool("joomscan"):
                jobs.append(Job(
                    cmd=["joomscan", "-u", base],
                    output_file=f"{netutil.safe_filename(host)}-{port.portid}.{scheme}.joomscan",
                    category="http",
                    host=host,
                    description=f"joomscan {base}",
                ))
            elif any(x in port.product for x in ("tomcat", "jboss")):
                # Tomcat manager login brute via hydra (no msfconsole).
                # JBoss exposure is also flagged by whatweb/nikto output.
                hydra = config.tool("hydra")
                if hydra and config.user_dict.exists() and config.pass_dict.exists():
                    ssl_flag = ["-S"] if port.ssl else []
                    jobs.append(Job(
                        cmd=[
                            hydra,
                            "-L", str(config.user_dict),
                            "-P", str(config.pass_dict),
                            "-e", "ns",
                            "-t", "8",
                            *ssl_flag,
                            "http-get",
                            f"{base}/manager/html",
                        ],
                        output_file=f"{netutil.safe_filename(host)}-{port.portid}.{scheme}.tomcat_brute",
                        category="brute",
                        host=host,
                        description=f"hydra tomcat {base}/manager/html",
                    ))

        return jobs
