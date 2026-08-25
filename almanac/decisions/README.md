---
title: Decisions
topics:
  - decisions
---

# Decisions

Decision pages record *why* a durable design choice exists. They are not
descriptions of current code — they explain the constraints that must survive
future refactors.

## Format

Each decision follows this structure (see `_templates/decision.md`):

- **Status** — Accepted / Superseded / Proposed
- **Context** — what problem forced a choice
- **Decision** — what was chosen
- **Consequences** — what becomes easier or harder
- **Invariants** — what future changes must preserve (the payload)
- **Alternatives Considered** — what was rejected and why

## Index

| Decision | Topic |
|----------|-------|
| [Discovery is address-family aware](discovery-is-address-family-aware.md) | masscan for IPv4, nmap `-6 -Pn` for IPv6; mixed lists split by family |
| [Masscan-gated discovery](masscan-gated-discovery.md) | _Superseded_ — nmap only enumerates hosts masscan found live |
