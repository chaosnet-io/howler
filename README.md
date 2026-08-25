# Howler

**Automated recon and enumeration scanner — modular rewrite of [nightcall](https://github.com/lpendergrass/nightcall).**

Howler preserves the battle-tested pipeline from nightcall (masscan discovery → nmap enumeration → service-targeted follow-up scans) while replacing the monolithic single-file design with a config-driven, plugin-based architecture built on modern Python.

```
                             __
                           .d$$b
                         .' TO$;\
                        /  : TP._;
                       / _.;  :Tb|
                      /   /   ;j$j
                  _.-"       d$$$$
                .' ..       d$$$$;
               /  /P'      d$$$$P. |\
              /   "      .d$$$P' |\^"l
            .'           `T$P^"""""  :
        ._.'      _.'                ;

         .:[ Howler v2.0.0 ]:. (nightcall reborn)
              ~ Automated Enumeration ~
```

---

## Features

- **Config-driven** — all port lists, NSE scripts, wordlists, rates, and tool paths live in `config.yaml`. No source edits needed.
- **Modular plugin architecture** — each protocol is a self-contained module. Adding support for a new service is a single file.
- **All-match dispatch** — unlike the original's `if/elif` chain, every matching module fires per port. An HTTPS port gets both `ssl_tls` (testssl.sh) and `http` (whatweb, ffuf, nikto, etc.) simultaneously.
- **Async runner** — `asyncio` with semaphore-based concurrency replaces `multiprocessing.dummy`. True async I/O, proper timeout handling, clean keyboard interrupt.
- **Graceful degradation** — missing tools are detected at startup and skipped with a warning. The scan continues with whatever is available.
- **Modern tool stack** — replaces several abandoned/outdated tools with actively maintained equivalents.
- **Rich output** — real progress bars and colour-coded console output via [Rich](https://github.com/Textualize/rich).
- **JSONL findings** — structured `run_state.jsonl` written alongside the usual raw text files.

---

## Pipeline

```
1. Import targets (IPs / CIDRs from file or single arg)
2. Host discovery (masscan — fast port sweep to find live hosts)
3. Port enumeration (nmap TCP + UDP with extensive NSE scripts)
4. XML import (parse nmap output into structured host/port data)
5. Follow-up scans (service-specific tools dispatched per open port)
6. Bruteforcing (optional, --brute flag — hydra; TFTP uses nmap NSE tftp-enum)
7. Summarize (grep-based summaries + run_state.jsonl)
8. Organize (sort output files into categorised subdirectories)
```

### Resuming interrupted scans

Howler writes `run_state.jsonl` incrementally as each job completes — one
record per job with a `status` field (`ok` | `failed` | `timeout`).

`--resume` skips any job whose description maps to `status == "ok"` in an
existing `run_state.jsonl`. Failed and timed-out jobs are re-run. Combine
with `-sP` to also skip masscan+nmap (using the existing XML in `xml/`):

```bash
# A scan got interrupted — resume without redoing completed work
sudo python3 howler.py --resume 10.10.10.5

# Or, if nmap already finished and only follow-ups were interrupted:
sudo python3 howler.py -sP --resume -f targets.txt
```

Without `--resume`, a fresh run truncates `run_state.jsonl` so old state
can't leak into the new run.

### External / internet-facing targets

Every default is tuned for a fast internal LAN. The `-x` / `--external` flag
retunes the pipeline for internet-facing targets:

- **Lower masscan rate** (2000 → 300 pps) — 2000 pps trips IDS/IPS and upstream
  rate-limits and risks the source address being null-routed.
- **Relaxed nmap RTT** (`--max-rtt-timeout` 300ms → 1250ms) — the LAN-tuned
  300ms silently drops ports on higher-latency internet paths.
- **No OS detection** (`-O`) — unreliable through firewalls, slow, and noisy.
- **UDP deep-enum skipped** — UDP scanning across the internet is slow and lossy
  (masscan still probes UDP during discovery; only the nmap UDP follow-up drops).
- **Curated attack-surface ports** — masscan discovery and nmap enumeration both
  use a focused external port set (web, mail, VPN, SSH/RDP/WinRM, DNS, and the
  databases/SMB/IPMI/X11 that are critical findings *if* exposed) instead of a
  full `-p-` sweep at internet latency. An explicit `masscan.ports` you set in
  `config.yaml` is still honoured.
- **DoS / crash-risk NSE scripts dropped** (e.g. `smb-vuln-ms17-010`). Intrusive
  vuln/exploit checks and the `http-put` file-write are **kept** — this is an
  authorised penetration-testing tool.

The external profile layers over `config.yaml`, so a stealthier rate, custom NSE
set, or explicit port list you've configured is still respected (the rate is
only ever lowered).

**Discovery bypass:** masscan gates which hosts nmap sees — a host it finds no
open port on is never enumerated. On external targets a firewall may silently
drop masscan's probes while services still answer nmap's more thorough `-Pn`
scan. For a known in-scope IP list, `--assume-up` skips masscan entirely and
nmaps every target directly. (On a large range, masscan discovery is usually
faster — it prunes dead space before nmap spends time on it.)

**Scope control:** `--exclude-file` passes an out-of-scope IP/CIDR list to both
masscan (`--excludefile`) and nmap (`--excludefile`), so neighbours sharing a
CIDR (shared hosting, upstream infra) are never touched. It works with or
without `-x`.

---

### IPv6 targets

Howler detects IPv4 vs IPv6 from the target strings themselves (single addresses
or CIDRs, in either `-f` or a single argument) and splits a mixed list by family:

- **IPv4** — unchanged: masscan discovery, then nmap enumeration.
- **IPv6** — masscan is IPv4-only (its IPv6 support is experimental), so IPv6
  targets bypass discovery and are enumerated directly via `nmap -6 -Pn`
  (implicit `--assume-up`).
- **IPv6 CIDRs** expand only for `/120` or longer (≤256 hosts); a larger prefix is
  refused rather than iterating 2⁶⁴ addresses — provide specific addresses or a
  small prefix.
- **Mixed lists** (IPv4 + IPv6 together) are split by family and re-joined into a
  single run and report. `--exclude-file` is handled per family too.
- Output filenames for IPv6 hosts replace `:` with `_`.

Link-local IPv6 with a scope (`fe80::1%eth0`) is not supported — target global
unicast addresses.

---

## Requirements

### Python

```
Python 3.10+
```

**Kali / Debian / Ubuntu** — pip is blocked system-wide (PEP 668), use apt instead:
```bash
apt-get install python3-yaml python3-rich
```

**Other systems:**
```bash
pip install pyyaml rich
```

Or run `sudo python3 howler.py --install-prereqs` and Howler will pick the right method automatically.

**NixOS** — pip and apt don't work on NixOS. Use the provided `shell.nix`:
```bash
nix-shell        # drops you into a shell with everything available
sudo python3 howler.py <target>
```
If you're using **Arch Linux**, btw — pacman for official packages, yay (or paru) for AUR, pip for the rest:
```bash
sudo pacman -S --needed python-yaml python-rich masscan nmap nikto nfs-utils hydra ipmitool curl ssh-audit wpscan testssl.sh impacket valkey rsync postgresql mariadb-clients
yay -S --needed whatweb wafw00f ike-scan ffuf gowitness joomscan python-dnsrecon onesixtyone-git kerbrute-bin smtp-user-enum-git
pip install --break-system-packages enum4linux-ng windapsearch
```
`rdp-sec-check` isn't packaged — grab it from GitHub:
```bash
git clone https://github.com/CiscoCX/rdp-sec-check /opt/rdp-sec-check
sudo ln -s /opt/rdp-sec-check/rdp-sec-check.pl /usr/local/bin/rdp-sec-check
```

### System Tools

Howler checks for each tool at startup and skips modules whose tools aren't found. Only `masscan` and `nmap` are strictly required to run the core pipeline — everything else is optional.

| Tool | Module | Replaces |
|---|---|---|
| `masscan` | discovery | masscan |
| `nmap` | portscan | nmap |
| `testssl.sh` | ssl_tls | `sslscan` + MSF CCS/heartbleed/ticketbleed |
| `whatweb` | http | whatweb |
| `wafw00f` | http | wafw00f |
| `ffuf` | http (--web) | `wfuzz` |
| `nikto` | http (--web) | nikto |
| `gowitness` | http | `cutycapt` + `xvfb-run` |
| `wpscan` | http (--web, Wordpress) | wpscan |
| `joomscan` | http (--web, Joomla) | joomscan |
| `hydra` | http (Tomcat), brute (--brute) | `medusa`; MSF `tomcat_mgr_login` |
| `enum4linux-ng` | smb | `enum4linux` |
| `ssh-audit` | ssh | MSF `ssh_enumusers` |
| `smtp-user-enum` | smtp | MSF `smtp_enum` |
| `onesixtyone` | snmp | MSF `snmp_login` |
| `ipmitool` | ipmi | MSF `ipmi_version` + `ipmi_cipher_zero` |
| `windapsearch` | ldap | — (new: anonymous bind user/group enum) |
| `kerbrute` | kerberos | — (new: user enumeration via AS-REQ) |
| `impacket-GetNPUsers` | kerberos | — (new: ASREPRoasting) |
| `curl` | winrm | — (new: WinRM banner check) |
| `rdp-sec-check` | rdp | — (new: RDP protocol/NLA downgrade checks) |
| `redis-cli` | redis | — (new: unauth INFO probe on 6379) |
| `rsync` | rsync | — (new: --list-only share enumeration on 873) |
| `impacket-mssqlclient` | mssql | — (new: null session connection probe on 1433) |
| `mysql` | mysql | — (new: version probe on 3306, separate from brute) |
| `psql` | postgres | — (new: version probe on 5432, separate from brute) |
| `dnsrecon` | dns | dnsrecon |
| `ike-scan` | ike | ike-scan |
| `showmount` | nfs | showmount |
| `nmap` | ftp, tftp brute | — (new: standalone NSE for ftp-anon + tftp-enum) |

**Note:** RMI is handled by the nmap NSE `rmi-vuln-classloader` script
(already in `nse_tcp`); no separate module is needed. TFTP brute uses
nmap's `tftp-enum` NSE script. MSF `ipmi_dumphashes` (CVE-2013-4786 RAKP)
has no widely-packaged standalone equivalent and is not replaced —
nmap's `ipmi-cipher-zero` NSE script (already in `nse_udp`) covers
cipher-zero detection.

**Kali Linux quick install:**
```bash
apt-get install python3-yaml python3-rich masscan nmap nikto whatweb wafw00f wpscan ike-scan nfs-common enum4linux-ng hydra smtp-user-enum dnsrecon testssl.sh onesixtyone ipmitool curl rdp-sec-check redis-tools rsync default-mysql-client postgresql-client -y
pip install ssh-audit impacket windapsearch --break-system-packages
go install github.com/ropnop/kerbrute@latest
go install github.com/sensepost/gowitness@latest
go install github.com/ffuf/ffuf/v2@latest
```

---

## Usage

```
sudo python3 howler.py [target] [options]
```

### Target (mutually exclusive)

```
single_address         single IP or CIDR (e.g. 10.0.0.1 or 10.0.0.0/24)
-f, --target-file      file with line-separated IPs/CIDRs
```

### Options

```
-sP, --skip-portscans  skip masscan/nmap, import existing XML from xml/
-i,  --iface           network interface for masscan and nmap
-b,  --brute           enable credential bruteforcing (mind lockout policies)
-w,  --web             enable extended web scans (ffuf, nikto, CMS scanners)
-x,  --external        external / internet-facing target profile (see below)
     --exclude-file P   file of out-of-scope IPs/CIDRs to exclude from
                        masscan and nmap (enforces engagement scope)
     --assume-up        skip masscan discovery; nmap every target directly
                        (for known in-scope IP lists behind silent-drop
                        firewalls). pairs well with -x
     --disable-resolve skip reverse hostname resolution
     --resume          skip jobs previously marked 'ok' in run_state.jsonl;
                       re-runs failed/timeout jobs. combine with -sP to also
                       skip masscan+nmap
     --config PATH      path to config YAML (default: config.yaml)
     --cleanup          re-sort output directory and exit
     --install-prereqs  install pyyaml and rich via pip
```

### Examples

```bash
# Scan a single host, full suite
sudo python3 howler.py 10.10.10.5

# Scan a /24, skip nmap on already-scanned hosts, enable web checks
sudo python3 howler.py -sP -w -f targets.txt

# Full scan with bruteforcing and extended web checks
sudo python3 howler.py -b -w 192.168.1.0/24

# External / internet-facing engagement, honouring a scope exclusion list
sudo python3 howler.py -x --exclude-file out-of-scope.txt -f in-scope.txt

# External scan of a known in-scope IP list behind a silent-drop firewall
sudo python3 howler.py -x --assume-up -f in-scope.txt

# Use a custom config
sudo python3 howler.py --config /etc/howler/config.yaml 10.0.0.1

# Re-sort a partially organized output directory
sudo python3 howler.py --cleanup

# Resume an interrupted scan (skips completed follow-up jobs)
sudo python3 howler.py -sP --resume -f targets.txt
```

---

## Configuration

Copy `config.yaml` and adjust as needed:

```yaml
concurrency:
  concurrent_tasks: 4      # parallel jobs
  task_timeout: 3600       # per-job timeout in seconds
  discovery_wait: 60       # extra wait after masscan estimate

masscan:
  rate: 2000               # packets/sec (increase carefully)
  retries: 2

nmap:
  large_host_threshold: 100  # hosts above this get top-1000 TCP only; below = full-port
  nse_tcp: "..."             # full NSE script list
  nse_udp: "..."

wordlists:
  user_dict: /usr/share/ncrack/minimal.usr
  pass_dict: /usr/share/seclists/Passwords/unix_passwords.txt
  snmp_dict: /usr/share/seclists/Miscellaneous/default-snmp-strings.txt
  http_fuzz_small: /usr/share/seclists/Discovery/Web-Content/common.txt
  http_fuzz_large: /usr/share/seclists/Discovery/Web-Content/big.txt

tools:
  # Override auto-detected paths if needed:
  # testssl.sh: /opt/testssl.sh/testssl.sh
  # gowitness: /home/user/go/bin/gowitness

features:
  randomize_jobs: false    # randomize job order to spread load across hosts
  jsonl_output: true       # write run_state.jsonl
```

---

## Output Structure

```
./
├── xml/                   nmap XML files
├── nmap/                  nmap .nmap text files
│   └── gnmap/             nmap .gnmap grep files
├── http/                  web tool output (whatweb, wafw00f, ffuf, nikto, wpscan...)
│   └── images/            gowitness screenshots
├── misc/                  DNS, NFS, IKE, IPMI, SSH audit, SNMP, TFTP-enum, FTP, LDAP, Kerberos, WinRM, RDP, Redis, RSync, MSSQL, MySQL, PostgreSQL
│   └── ssl/               testssl.sh output
├── brute/                 hydra output
├── nmap.summary.txt       open ports and OS detection summary
├── http.summary.txt       whatweb summaries
├── brute.summary.txt      successful credentials
├── run_state.jsonl         structured findings (one JSON object per completed job)
├── hostnames.txt          IP → hostname mappings
└── Howler_YYYY-Mon-DD_*.log  full debug log
```

---

## Extending Howler

Adding support for a new service is straightforward:

**1. Create `modules/myservice.py`:**
```python
from config import Config
from models import Job, PortInfo
from modules import BaseModule

class MyServiceModule(BaseModule):
    required_tools = ["mytool"]

    def match(self, port: PortInfo) -> bool:
        return port.portid == "9999" or port.name == "myservice"

    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]:
        tool = config.tool("mytool")
        if not tool:
            return []
        return [Job(
            cmd=[tool, "--target", host, "--port", port.portid],
            output_file=f"{host}-{port.portid}.misc.myservice",
            category="misc",
            host=host,
            description=f"mytool {host}:{port.portid}",
        )]
```

**2. Register it in `modules/__init__.py`:**
```python
from modules.myservice import MyServiceModule
# ...
registry.register(MyServiceModule())
```

That's it. Howler will automatically check for `mytool` at startup and dispatch jobs to your module for any matching ports.

---

## Differences from nightcall

| | nightcall | Howler |
|---|---|---|
| Structure | Single 712-line file | Package (19 files) |
| Config | Hardcoded constants | `config.yaml` |
| Service dispatch | `if/elif` chain (first match) | Registry (all matches) |
| Concurrency | `multiprocessing.dummy` (threads) | `asyncio` |
| Process spawning | `shell=True` throughout | `create_subprocess_exec` |
| Progress | Fake tqdm time estimate | Rich live progress |
| Missing tools | Hard crash | Startup warning, graceful skip |
| Data model | Raw dicts | Typed dataclasses |
| Output | Raw files only | Raw files + `run_state.jsonl` |
| Python | 3.6+ | 3.10+ |

---

## License & Attribution

Howler is a derivative work of [nightcall](https://github.com/lpendergrass/nightcall) by Lance Pendergrass (Walmart Inc., 2017), which is licensed under the [Apache License 2.0](LICENSE).

Substantial modifications have been made, including a full architectural redesign. See [NOTICE](NOTICE) for details.

---

## Responsible Use

Only use against systems you own or have explicit written authorisation to test. Unauthorised scanning is illegal in most jurisdictions.
