---
title: Components
topics:
  - components
  - module-system
---

# Components

Components are independently understandable subsystems. Each can be understood and
modified without reading the entire codebase. The most important component is the
**module system**: every protocol scanner is a self-contained `BaseModule`
subclass in `modules/`, registered once and dispatched purely by port match.

## Component Index

| Component | Source | Description |
|-----------|--------|-------------|
| Module system | `modules/__init__.py` | `BaseModule` + `ModuleRegistry` dispatch |

## Design Principle

Each service scanner is a single file in `modules/` exposing three things, defined
by the `BaseModule` ABC in `modules/__init__.py`:

```python
class BaseModule(ABC):
    required_tools: list[str] = []            # checked at startup; missing → skipped
    def match(self, port: PortInfo) -> bool: ...   # does this module fire for this port?
    def jobs(self, host: str, port: PortInfo, config: Config) -> list[Job]: ...
```

Modules only import `config`, `models`, `netutil`, and `modules` — never
`runner`, `scanner`, or `output`. They are pure `(host, PortInfo, Config) →
list[Job]` functions: no subprocess spawning, no file I/O, no ordering
assumptions. `netutil` supplies the address-family helpers (`bracket`,
`hostport`, `safe_filename`) shared by every module. The registry
(`build_default_registry`) instantiates them once and `dispatch()` concatenates
every match's jobs, so a port can trigger several modules simultaneously.

To add a service scanner: create `modules/<name>.py`, implement `match`/`jobs`,
and register it in `build_default_registry()` (see the repo `README.md` "Extending
Howler").
