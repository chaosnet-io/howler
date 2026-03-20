"""
HTTP/HTTPS module.
Tools: wafw00f, whatweb, ffuf (replaces wfuzz), nikto, gowitness (replaces cutycapt+xvfb),
       wpscan, joomscan.
MSF http_list/http_put/http_host/http_crawler removed — nikto and ffuf cover the same ground.
"""

from __future__ import annotations

from config import Config
from models import Job, PortInfo
from modules import BaseModule


class HttpModule(BaseModule):
    required_tools = ["whatweb", "wafw00f", "ffuf", "nikto", "gowitness", "wpscan", "joomscan"]

    def match(self, port: PortInfo) -> bool:
        return port.is_http

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        jobs: list[Job] = []
        scheme = port.scheme
        base = f"{scheme}://{host}:{port.portid}"

        # Always-on: whatweb, wafw00f, gowitness screenshot
        if config.tool("whatweb"):
            jobs.append(Job(
                cmd=["whatweb", "-vv", base],
                output_file=f"{host}-{port.portid}.{scheme}.whatweb",
                category="http",
                host=host,
                description=f"whatweb {base}",
            ))

        if config.tool("wafw00f"):
            jobs.append(Job(
                cmd=["wafw00f", "-v", base],
                output_file=f"{host}-{port.portid}.{scheme}.waf",
                category="http",
                host=host,
                description=f"wafw00f {base}",
            ))

        if config.tool("gowitness"):
            jobs.append(Job(
                cmd=[
                    "gowitness", "screenshot",
                    "--url", base,
                    "--destination", f"{host}-{port.portid}.png",
                    "--disable-logging",
                ],
                output_file=f"{host}-{port.portid}.png",
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
                jobs.append(Job(
                    cmd=[
                        "ffuf",
                        "-w", fuzz_list,
                        "-u", f"{base}/FUZZ",
                        "-o", f"{host}-{port.portid}.{scheme}.ffuf",
                        "-of", "json",
                        "-fc", "302,400,401,403,404",
                        "-r",
                        "-recursion", "-recursion-depth", "2",
                        "-s",
                    ],
                    output_file=f"{host}-{port.portid}.{scheme}.ffuf",
                    category="http",
                    host=host,
                    description=f"ffuf {base}",
                ))

            if config.tool("nikto"):
                ssl_flag = ["-ssl"] if port.ssl else []
                jobs.append(Job(
                    cmd=[
                        "nikto",
                        "-nolookup", "-nointeractive",
                        "-timeout", "5",
                        "-evasion", "1",
                        *ssl_flag,
                        "-h", f"{host}:{port.portid}",
                    ],
                    output_file=f"{host}-{port.portid}.{scheme}.nikto",
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
                    output_file=f"{host}-{port.portid}.{scheme}.wpscan",
                    category="http",
                    host=host,
                    description=f"wpscan {base}",
                ))
            elif "joomla" in cms and config.tool("joomscan"):
                jobs.append(Job(
                    cmd=["joomscan", "-u", base],
                    output_file=f"{host}-{port.portid}.{scheme}.joomscan",
                    category="http",
                    host=host,
                    description=f"joomscan {base}",
                ))
            elif any(x in port.product for x in ("tomcat", "jboss")):
                # Tomcat/JBoss: use MSF if available
                msf = config.tool("msfconsole")
                if msf:
                    ssl_val = str(port.ssl).lower()
                    for module, ext in [
                        ("auxiliary/scanner/http/tomcat_mgr_login", "tomcat_mgr_login"),
                        ("auxiliary/scanner/http/jboss_vulnscan", "jboss_vulnscan"),
                    ]:
                        jobs.append(Job(
                            cmd=[
                                msf, "-q", "-x",
                                f"use {module}; set THREADS 6; set RHOSTS {host}; "
                                f"set RPORT {port.portid}; set SSL {ssl_val}; run; exit",
                                "-o", f"{host}-{port.portid}.msf.{ext}",
                            ],
                            output_file=f"{host}-{port.portid}.msf.{ext}",
                            category="msf",
                            host=host,
                            description=f"MSF {module} {host}:{port.portid}",
                        ))

        return jobs
