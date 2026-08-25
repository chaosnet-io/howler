---
title: Output contracts
topics:
  - reference
  - output-format
  - resume
  - addressing
sources:
  - id: runner
    type: file
    path: runner.py
    note: _result_to_entry() defines the run_state.jsonl record
  - id: organizer
    type: file
    path: output/organizer.py
    note: _POST_NMAP_CMDS / _FINAL_CMDS define the directory layout
  - id: pipeline
    type: file
    path: howler.py
    note: FINDINGS_PATH and load_resume_state()
---

# Output contracts

Exact on-disk formats that other phases and `--resume` depend on. Keep these
tables current; changing a field name or naming convention is a contract change.

## `run_state.jsonl` (resume state)

One JSON object per completed job, appended incrementally by
`AsyncJobRunner.run_all()`. File path is the constant `FINDINGS_PATH =
Path("run_state.jsonl")` in `howler.py`.

| Field | Type | Meaning |
|-------|------|---------|
| `host` | string | Target IP as it was passed to the job |
| `category` | string | `xml` \| `http` \| `ssl` \| `smb` \| `dns` \| `misc` \| `brute` |
| `tool` | string | `job.cmd[0]` (basename of the invoked binary) |
| `description` | string | **Resume key.** Unique per (tool, host, port, variant) |
| `output_file` | string | Relative output path the job is expected to write |
| `returncode` | int | Process exit code (`-1` if the tool was not found) |
| `status` | string | `ok` \| `failed` \| `timeout` |
| `duration` | number | Wall-clock seconds, 2-dp |
| `timed_out` | bool | Whether the job hit `task_timeout` |

Resume rule: `--resume` loads this file into `{description: status}` and
`filter_completed_jobs()` skips only `status == "ok"` records. A `description`
collision between two distinct jobs would silently skip real work — the
uniqueness is an invariant, not a convention.

## Directory layout

Produced by `output/organizer.py` shell moves (extension/pattern driven).

| Directory | Contents |
|-----------|----------|
| `xml/` | nmap `-oA` `.xml` files (imported by `scanner/xml_parser.py`) |
| `nmap/` + `nmap/gnmap/` | nmap `.nmap` / `.gnmap` text files |
| `http/` + `http/images/` | web tool output + gowitness `.png` screenshots |
| `misc/` + `misc/ssl/` | DNS, NFS, IKE, IPMI, SSH, SNMP, FTP, LDAP, Kerberos, WinRM, RDP, Redis, RSync, MSSQL, MySQL, PostgreSQL, TFTP, testssl.sh |
| `brute/` | hydra output |
| (root) | `nmap.summary.txt`, `http.summary.txt`, `brute.summary.txt`, `hostnames.txt`, `run_state.jsonl`, `Howler_*.log` |

## File naming

| Producer | Pattern | Notes |
|----------|---------|-------|
| nmap | `{host}.tcp.{xml,nmap,gnmap}`, `{host}.udp.{…}` | from `-oA {host}.tcp` / `{host}.udp` |
| http module | `{host}-{port}.{scheme}.{whatweb,waf,ffuf,nikto,wpscan,joomscan,tomcat_brute}` | `scheme` ∈ `http`/`https` |
| ssl_tls | `{host}-{port}.misc.ssl` | |
| misc modules | `{host}.misc.{rdns,nfs,nat-ike,ike,ldap_users,ldap_groups}` or `{host}-{port}.misc.{tool}` | |
| smb | `smb-{host}.misc.enum` | |
| brute | `{host}.{port.name}.brute` | |

**Addressing:** `{host}` is the *raw* address in `Job.description` and
`run_state.jsonl`, but output filenames use `netutil.safe_filename(host)` — IPv4
unchanged, IPv6 colons become `_` (e.g. `2001:db8::5` → `2001_db8__5`). See
[`netutil.py`](../../netutil.py).
