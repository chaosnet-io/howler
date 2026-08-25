---
title: Discovery is address-family aware
topics:
  - decisions
  - discovery
  - addressing
sources:
  - id: pipeline
    type: file
    path: howler.py
    note: run_pipeline() splits targets by family before discovery
  - id: discovery
    type: file
    path: scanner/discovery.py
    note: run_discovery() is masscan/IPv4-only; _masscan_exclude_file()
  - id: netutil
    type: file
    path: netutil.py
    note: split_by_family() and the address-family helpers
---

# Discovery is address-family aware

## Status

Accepted

## Context

masscan is IPv4-only in practice: its IPv6 support is experimental and unusable
for the small ranges a pentest actually targets. A client handing over a mixed
IPv4/IPv6 target list cannot be served by a single discovery path.

## Decision

Host discovery is split by address family:

- IPv4 targets go through masscan (unchanged).
- IPv6 targets bypass masscan entirely and are enumerated directly by nmap
  `-6 -Pn` (an implicit `--assume-up`).
- A mixed list is split with `netutil.split_by_family()` (CIDR-aware); the two
  families are discovered separately and merged before nmap.
- IPv6 CIDRs expand only for `/120` or longer (≤256 hosts); larger prefixes are
  refused with an actionable error.
- The masscan exclude file is IPv4-filtered; nmap still receives the full file.

## Consequences

- **Easier:** mixed client lists "just work" in one run and one report; IPv6 no
  longer depends on masscan's experimental path.
- **Harder:** there is no IPv6 host-discovery *pruning* — every provided IPv6
  address is enumerated. Large or sparse IPv6 sweeps are out of scope.
- **Foreclosed:** masscan is never asked to scan IPv6.

## Invariants

Future changes must preserve:

1. masscan never receives an IPv6 target — `run_discovery` is IPv4-only.
2. IPv6 enumeration always uses nmap `-Pn` (and `-6`), never masscan discovery.
3. Mixed target lists are split with `split_by_family()` before discovery and
   re-joined into one `hosts` dict.
4. IPv6 CIDR expansion is capped at `/120`; a larger prefix errors, never OOMs.
5. The masscan exclude file is IPv4-filtered (`_masscan_exclude_file`); nmap
   still receives the full exclude file.

## Alternatives Considered

**Extend masscan with `--source-ip`/`--router-mac` IPv6 plumbing** — rejected.
masscan's IPv6 scanning is experimental and unusable for small ranges; the added
complexity doesn't buy reliable discovery.

**nmap `-6 -sn` ping sweep for IPv6 discovery** — rejected for now. It adds a
second discovery parser for little benefit over the existing `-Pn` enumeration,
since nmap already probes every target regardless of up/down state. Revisit if
IPv6 host pruning is ever needed.
