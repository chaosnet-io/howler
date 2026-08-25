---
title: Architecture
topics:
  - architecture
---

# Architecture

Howler is built around a single **linear pipeline** orchestrated by
`run_pipeline()` in `howler.py`. The spine is a sequence of phases that transform
an input target list into structured findings: targets → live hosts → open ports
→ per-service tool jobs → summaries. Between phases, the shared vocabulary is a
small set of dataclasses in `models.py` (`HostScan`, `PortInfo`, `Job`); everything
else (`config.py`, `scanner/`, `modules/`, `output/`) produces or consumes those.

## Subsystems

| Subsystem | Source | Purpose |
|-----------|--------|---------|
| CLI + pipeline | `howler.py` | Arg parsing, phase orchestration, resume state, tool check |
| Config | `config.py` | Defaults + `config.yaml` merge, tool/wordlist resolution, external profile |
| Data models | `models.py` | `HostScan`, `PortInfo`, `Job`, `ScanResult` |
| Async runner | `runner.py` | Semaphore-bounded subprocess execution + `run_state.jsonl` writes |
| Discovery | `scanner/discovery.py` | masscan live-host sweep |
| Port scanning | `scanner/portscan.py` | nmap TCP/UDP job builders + hostname resolution |
| XML import | `scanner/xml_parser.py` | nmap XML → `HostScan`/`PortInfo` |
| Modules | `modules/` | One file per protocol; each emits `Job`s for matching ports |
| Output | `output/` | `organizer.py` (file sorting) + `summarizer.py` (grep summaries) |

## Overall Flow

```
targets (IPs/CIDRs)
      │  import_hosts()          → dict[addr, HostScan]
      ▼
 discovery (IPv4: masscan)       → live_hosts.txt → list[IPv4]
 discovery (IPv6: nmap -6 -Pn)   → every IPv6 target treated up
      │  (skipped by --assume-up / -sP)
      ▼
 nmap TCP + UDP per host         → {host}.tcp.xml / {host}.udp.xml
      ▼
 xml_parser.parse_xml_files()    → HostScan { port_key: PortInfo }
      ▼
 registry.dispatch(host, port)   → follow-up Job list (all matching modules)
      ▼
 (optional) BruteModule          → hydra / nmap tftp-enum jobs
      ▼
 summarizer.run() + organizer.final_cleanup()   → summaries + sorted dirs
```

## Ownership Boundaries

- **The pipeline never shells out directly** for tool jobs; it hands `Job`s to
  `AsyncJobRunner`, which uses `create_subprocess_exec` (no shell) except where a
  `Job.shell = True` escape hatch is explicitly set.
- **Modules only import `config`, `models`, `modules`** — never `runner`,
  `scanner`, or `output`. They are pure `(host, PortInfo, Config) → list[Job]`
  functions.
- **Discovery gates enumeration.** nmap only runs against hosts masscan found
  live (or every target under `--assume-up` / `-sP`). See
  [Masscan-gated discovery](../decisions/masscan-gated-discovery.md).

## Detailed Pages

- [Scan Pipeline](pipeline.md) — the end-to-end phase sequence and what each phase reads/writes.
