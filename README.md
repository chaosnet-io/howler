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
- **JSONL findings** — structured `findings.jsonl` written alongside the usual raw text files.

---

## Pipeline

```
1. Import targets (IPs / CIDRs from file or single arg)
2. Host discovery (masscan — fast port sweep to find live hosts)
3. Port enumeration (nmap TCP + UDP with extensive NSE scripts)
4. XML import (parse nmap output into structured host/port data)
5. Follow-up scans (service-specific tools dispatched per open port)
6. Bruteforcing (optional, --brute flag — hydra + MSF TFTP)
7. Summarize (grep-based summaries + findings.jsonl)
8. Organize (sort output files into categorised subdirectories)
```

---

## Requirements

### Python

```
Python 3.10+
pip install pyyaml rich
```

Or use `--install-prereqs` to have Howler install them automatically.

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
| `enum4linux-ng` | smb | `enum4linux` |
| `ssh-audit` | ssh | MSF `ssh_enumusers` |
| `smtp-user-enum` | smtp | MSF `smtp_enum` |
| `dnsrecon` | dns | dnsrecon |
| `ike-scan` | ike | ike-scan |
| `showmount` | nfs | showmount |
| `hydra` | brute (--brute) | `medusa` |
| `msfconsole` | snmp, ipmi, rmi, tftp | msfconsole |

**Kali Linux quick install:**
```bash
apt-get install masscan nmap nikto whatweb wafw00f wpscan ike-scan nfs-common enum4linux-ng hydra smtp-user-enum dnsrecon testssl.sh -y
pip install ssh-audit
go install github.com/sensepost/gowitness@latest
go install github.com/ffuf/ffuf/v2@latest
pip install pyyaml rich
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
     --disable-resolve skip reverse hostname resolution
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

# Use a custom config
sudo python3 howler.py --config /etc/howler/config.yaml 10.0.0.1

# Re-sort a partially organized output directory
sudo python3 howler.py --cleanup
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
  jsonl_output: true       # write findings.jsonl
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
├── msf/                   Metasploit module output
├── misc/                  DNS, NFS, IKE, IPMI, SSH audit
│   └── ssl/               testssl.sh output
├── brute/                 hydra / MSF brute output
├── nmap.summary.txt       open ports and OS detection summary
├── msf.summary.txt        MSF positive findings
├── http.summary.txt       whatweb summaries
├── brute.summary.txt      successful credentials
├── findings.jsonl         structured findings (one JSON object per completed job)
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
| Output | Raw files only | Raw files + `findings.jsonl` |
| Python | 3.6+ | 3.10+ |

---

## License & Attribution

Howler is a derivative work of [nightcall](https://github.com/lpendergrass/nightcall) by Lance Pendergrass (Walmart Inc., 2017), which is licensed under the [Apache License 2.0](LICENSE).

Substantial modifications have been made, including a full architectural redesign. See [NOTICE](NOTICE) for details.

---

## Responsible Use

Only use against systems you own or have explicit written authorisation to test. Unauthorised scanning is illegal in most jurisdictions.
