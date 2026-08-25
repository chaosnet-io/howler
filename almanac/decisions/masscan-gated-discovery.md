---
title: Masscan-gated discovery
topics:
  - decisions
  - discovery
  - addressing
sources:
  - id: discovery
    type: file
    path: scanner/discovery.py
    note: run_discovery(), _build_masscan_cmd(), _convert_masscan_output()
  - id: pipeline
    type: file
    path: howler.py
    note: run_pipeline() decides discovery vs --assume-up vs -sP
---

# Masscan-gated discovery

## Status

Superseded by [Discovery is address-family aware](discovery-is-address-family-aware.md)

## Context

`nightcall` (Howler's ancestor) used masscan for host discovery because a full
nmap sweep over a large range is slow: masscan's fast SYN/ICMP scan prunes dead
address space so nmap only spends time on hosts that actually have open ports.
Howler preserved that pipeline shape.

## Decision

Host discovery runs masscan (`--ping --open-only -oB masscan.bin`) over the target
list; its output is converted to `live_hosts.txt`, and **nmap enumerates only the
live IPs**. Two opt-outs exist for cases where masscan's model breaks down:

- `--assume-up` — skip masscan entirely and nmap (`-Pn`) every provided target.
- `-sP` — skip both discovery and nmap, importing existing XML from `xml/`.

## Consequences

- **Easier:** large CIDR sweeps stay fast; nmap never wastes time on dead hosts.
- **Harder:** a firewall that silently drops masscan's probes while still answering
  nmap hides hosts from enumeration — that is exactly why `--assume-up` exists.
- **Foreclosed (today):** the live-host extraction (`_convert_masscan_output` →
  `awk '{print $4}'`) and the host-count estimate (`2 ** (32 - prefix)`) both
  assume IPv4; masscan's IPv6 support is experimental and unsuitable for small
  ranges, so IPv6 discovery is effectively unsupported by this phase.

## Invariants

Future changes must preserve:

1. A host masscan finds no open port on is **never** enumerated by nmap, unless
   `--assume-up` or `-sP` is given.
2. The `hosts` dict is **rebuilt from discovered live IPs** after discovery
   (`howler.py`); original target entries are not carried forward.
3. `live_hosts.txt` is derived from masscan `-oL` field 4 (`$4`) — an IPv4 layout.
   Any address-family generalization must also update `_count_hosts` /
   `_estimate_scan_duration`, which use IPv4 prefix arithmetic.

## Alternatives Considered

**nmap `-sn` ping sweep for discovery** — rejected as the *default*: slower than
masscan for large ranges, though it is the likely path for IPv6 (see
[DEVSTATE.md](../../DEVSTATE.md)).

**nmap `-Pn` against every target always** — rejected as the default: no dead-space
pruning. Adopted as the opt-in `--assume-up` flag instead.
