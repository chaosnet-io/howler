# Howler Development State

_Last reviewed: 2026-08-25_

> This file lives at the **repo root** (sibling to `README.md` and `/almanac`).
> It holds the **volatile** view — what to work on next and what's currently
> broken. Durable design docs go in [`almanac/`](almanac/README.md); this file
> does not.

---

## Current Focus

IPv6 support has landed end-to-end: family-aware discovery, `-6` nmap jobs, IPv6
XML import, bracketed module URLs, sanitized output filenames, the `/120` CIDR
guard, and mixed-family target/exclude handling. Remaining work is hardening the
long tail of third-party tool IPv6 support and link-local handling.

---

## Known Limitations

- **Link-local IPv6 (`fe80::…%eth0`) unsupported** — `ipaddress` rejects the `%`
  scope zone; only global unicast addresses work. Documented in `README.md`.
- **Third-party IPv6 support unverified** — `rdp-sec-check`, `impacket-mssqlclient`,
  `enum4linux-ng`, `testssl.sh`, and `windapsearch` may have partial or no IPv6
  support. Jobs that fail simply record `status: "failed"` in `run_state.jsonl`.
- **No IPv6 reverse-DNS sweep** — the dns module's `/24` reverse sweep is IPv4-only
  and skipped for IPv6; forward DNS (PTR-derived domain) still runs.
- **No sparse-/64 IPv6 discovery** — IPv6 targets are enumerated directly (no host
  pruning); a `/64`+ sweep is refused. Large sparse ranges need an external
  active-address-discovery pass first.

---

## Next Milestones

1. **Verify/handle per-tool IPv6** — test rdp-sec-check, impacket, enum4linux-ng,
   testssl.sh over IPv6; add per-tool flags (e.g. testssl `-6`) where the
   installed tool requires them.
2. **IPv6 reverse-DNS sweep** — add `ip6.arpa` nibble-zone reverse enumeration for
   in-scope IPv6 prefixes.
3. **Link-local IPv6** — accept `%iface` scope zones and pass `-e <iface>` to nmap.

---

## Recently Completed

- **IPv6 support** (2026-08-25) — family-aware discovery, `-6` nmap jobs, IPv6 XML
  import, bracketed module URLs, sanitized output filenames, `/120` CIDR guard,
  mixed-family target/exclude handling, and tests.
- **Bootstrapped the almanac** (2026-08-25) — added `almanac/` + `DEVSTATE.md`.

---

## Durable Documentation

Architecture, decisions, guides, and exact contracts live in
[`almanac/`](almanac/README.md).

- **`almanac/`** — how the system is designed to keep working
- **`DEVSTATE.md`** (this file) — what to work on next and what's currently broken
- **`README.md`** — how end users install and run the project
