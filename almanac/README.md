---
title: Howler Almanac
topics:
  - overview
sources:
  - id: project-readme
    type: file
    path: README.md
    note: Public product overview and usage
  - id: devstate
    type: file
    path: DEVSTATE.md
    note: Current development focus and known limitations
---

# Howler Almanac

Howler is an automated recon and enumeration scanner built around a **linear scan
pipeline** — `masscan` discovery → `nmap` enumeration → XML import → per-service
follow-up jobs → optional bruteforce → summarize → organize. It is a config-driven,
plugin-based Python 3.10+ rewrite of `nightcall.py`: the CLI orchestrates the
pipeline in `howler.py`, each network protocol is a self-contained module in
`modules/`, and every tool invocation is a `Job` dataclass executed by an asyncio
runner.

This almanac explains **intent and cross-file behavior**. The code is
authoritative — when they disagree, fix the wiki, not the code.

## Start Here

- For the complete runtime flow, read [Architecture](architecture/README.md) and
  its [Scan Pipeline](architecture/pipeline.md) page.
- To add a new service scanner, see the module contract in
  [Components](components/README.md).
- For exact on-disk formats (resume state, output naming, directory layout), see
  [Reference](reference/README.md).
- To understand *why* host discovery works the way it does before changing it, see
  [Masscan-gated discovery](decisions/masscan-gated-discovery.md).

## Critical Invariants

<!-- The rules a change must never silently break. Each maps to a decisions/ or
     reference/ page. Verify against these before landing a diff. -->

1. **Discovery is address-family aware.** IPv4 hosts are gated by masscan (a host
   masscan finds no open port on is never enumerated); IPv6 targets bypass masscan
   and are enumerated directly via `nmap -6 -Pn`. `--assume-up` and `-sP` override
   discovery as before. See
   [Discovery is address-family aware](decisions/discovery-is-address-family-aware.md).
2. **Module dispatch is all-match, not first-match.** Every module whose
   `match()` accepts a port fires for that port — e.g. an HTTPS port runs both
   `ssl_tls` and `http`. See [Scan Pipeline](architecture/pipeline.md).
3. **Resume keys on `Job.description`, which must be unique** per (tool, host,
   port, variant). `--resume` skips only `status == "ok"` records in
   `run_state.jsonl`. See [Output contracts](reference/output-contracts.md).

## Sections

| Section | Purpose |
|---------|---------|
| [Architecture](architecture/README.md) | Runtime flows, subsystem boundaries, and ownership |
| [Components](components/README.md) | Internals of independently understandable subsystems |
| [Guides](guides/README.md) | Task-oriented procedures for developers and operators |
| [Decisions](decisions/README.md) | Design choices and constraints future work must preserve |
| [Reference](reference/README.md) | Exact settings, events, key bindings, and file formats |

## Accuracy

This wiki explains intent and cross-file behavior. Current code is authoritative
when it disagrees — update the wiki, not the code. Volatile "what's next / what's
broken" notes live in `DEVSTATE.md`, not here.
