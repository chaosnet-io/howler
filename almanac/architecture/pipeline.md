---
title: Scan Pipeline
topics:
  - architecture
  - pipeline
  - discovery
  - enumeration
  - addressing
sources:
  - id: pipeline-orchestrator
    type: file
    path: howler.py
    note: run_pipeline() and __main__ orchestrate every phase below
  - id: discovery
    type: file
    path: scanner/discovery.py
    note: masscan live-host sweep
  - id: portscan
    type: file
    path: scanner/portscan.py
    note: nmap TCP/UDP job builders
  - id: xml-parser
    type: file
    path: scanner/xml_parser.py
    note: nmap XML to HostScan/PortInfo
---

# Scan Pipeline

The pipeline turns a target list (IPs/CIDRs, single arg or `-f` file) into a set
of categorized output files and summaries. It runs once per invocation under
`asyncio.run()`; the only branch points are the CLI flags (`-sP`, `--assume-up`,
`--external`, `--brute`, `--web`, `--resume`).

## Flow

```
  import_hosts()          target line → ipaddress (ip_network/ip_address) → HostScan
        │
  split_by_family()       targets → IPv4 | IPv6
        │
  run_discovery() (IPv4)  masscan --ping --open-only -oB masscan.bin
        │                 → masscan --readscan -oL | awk $4 → live_hosts.txt
        │  (IPv6: no masscan — every address → nmap -6 -Pn)
        ▼
  tcp_scan_job / udp_scan_job   nmap -sSV/-sUV -Pn -oA {host}.tcp|.udp
        │                        full-port vs top-1000 vs curated (external)
        ▼
  parse_xml_files()       *.xml → HostScan(addr, ports{port_key: PortInfo})
        ▼
  registry.dispatch()     every matching module emits Jobs per open port
        ▼
  BruteModule (--brute)   hydra per auth port; nmap tftp-enum for 69/tftp
        ▼
  summarizer.run()        grep summaries + failed-job tally from run_state.jsonl
  organizer.final_cleanup()   mv outputs into xml/ nmap/ http/ misc/ brute/
```

## Phase / Step Details

### 1. Import targets — `howler.py::import_hosts`

Parses each non-comment line through `ipaddress.ip_network` (if it contains `/`)
or `ipaddress.ip_address`, then stores `HostScan(address=…)`. The `ipaddress`
module is address-family aware, so both IPv4 and IPv6 literals parse — but the
pipeline **downstream** of this step still assumes IPv4 in several places (see
[DEVSTATE.md](../../DEVSTATE.md) and [Addressing](../reference/output-contracts.md)).

### 2. Discovery — masscan (IPv4) + implicit `--assume-up` (IPv6)

`run_pipeline` splits targets by family (`netutil.split_by_family`). IPv4 goes
through `run_discovery`, which runs masscan (`--ping --open-only`), writes
`masscan.bin`, converts to `masscan.txt` (`-oL`), and extracts the live-IP column
into `live_hosts.txt`; those live IPs **replace** the IPv4 hosts. IPv6 targets
bypass masscan entirely (its IPv6 support is experimental) and are enumerated
directly by nmap `-6 -Pn` — an implicit `--assume-up`. The two families merge into
one `hosts` dict. `--assume-up` bypasses this phase for everything; `-sP` bypasses
both discovery and nmap.

### 3. Port enumeration — `scanner/portscan.py`

Builds one nmap TCP job per host (`-sSV -Pn -n`, plus `-O` unless external) and,
when `config.scan_udp`, one UDP job (`-sUV`). Depth is adaptive: full `-p-` for
small host sets, `--top-ports 1000` above `nmap_large_host_threshold`, or a fixed
curated set under the external profile. Output base is `{host}.tcp` / `{host}.udp`
(`-oA`), producing `.xml`, `.nmap`, `.gnmap`.

### 4. XML import — `scanner/xml_parser.py::parse_xml_files`

Parses every `*.xml` in `xml/` (excluding `masscan.xml`), extracting only hosts
whose address is in the `known_hosts` set, then populating `HostScan.ports`. Only
`addrtype == "ipv4"` is currently read — an IPv6 host emits `addrtype == "ipv6"`
and is dropped here.

### 5. Follow-up dispatch — `modules/`

For every open port, `registry.dispatch(host, port, config)` concatenates jobs
from **all** modules whose `match(port)` returns true (all-match, not first-match).
Each module is a pure `(host, PortInfo, Config) → list[Job]` function.

### 6. Bruteforce — `modules/brute.py`

Only when `--brute` is set. Auth-protocol ports get a hydra job; port 69/tftp gets
an nmap `tftp-enum` job.

### 7. Summarize + organize — `output/`

`summarizer.run()` runs grep-based summaries (`nmap.summary.txt`,
`http.summary.txt`, `brute.summary.txt`) and tallies non-`ok` jobs from
`run_state.jsonl`. `organizer.final_cleanup()` moves outputs into the categorized
directory tree.

## Boundaries & Guarantees

- A host that reaches follow-up dispatch always has at least one open port
  (`hosts` is filtered by `has_ports()` in `howler.py`).
- Discovery is the only phase that talks to masscan; enumeration is the only phase
  that builds nmap scan jobs.
- Module output filenames are derived from the host string verbatim — for IPv6
  this puts `:` characters into filenames (see
  [Output contracts](../reference/output-contracts.md)).

## Related

- [Masscan-gated discovery](../decisions/masscan-gated-discovery.md)
- [Output contracts](../reference/output-contracts.md)
