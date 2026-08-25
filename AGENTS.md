# Agent instructions: the /almanac

This project keeps a **durable design wiki at `/almanac`**. It explains how the
system is designed to work and which invariants must not break — so you can get
oriented without reading the whole codebase.

## Rule 1 — Read before you write

Before writing code, open **`/almanac/README.md`**. It lists the project's
critical invariants and the reading paths into each section. Follow only the path
relevant to your task:

- `architecture/` — runtime flow and subsystem boundaries
- `components/` — a single subsystem in isolation
- `reference/` — exact values (config keys, event payloads, file formats)
- `guides/` — how to perform a specific task
- `decisions/` — *why* something is the way it is (read before changing it)

If your planned change would violate a stated invariant, stop and raise it before
proceeding.

## Rule 2 — Update after you change the design

If your change alters runtime flow, adds a subsystem, makes a lasting design
decision, or changes an exact contract, update the matching almanac page (and its
section `README.md` index + `topics.yaml`). Do **not** update it for bug fixes,
behavior-preserving refactors, or detail the code already makes obvious. The
almanac is not a changelog.

**Code is authoritative:** when code and the almanac disagree, fix the almanac.

Volatile "what's next / what's broken" notes belong in `DEVSTATE.md` at the repo
root (create it there if it doesn't exist), not the almanac.
