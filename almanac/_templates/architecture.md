---
title: {{Page Title}}
topics:
  - architecture
  - {{domain-topic}}
sources:
  - id: {{slug}}
    type: file
    path: {{path/to/source}}
    note: {{what this file is}}
---

# {{Page Title}}

{{One paragraph: what this flow/subsystem is and why it's the spine of this part
of the system.}}

## {{Flow / Lifecycle}}

```
{{ASCII diagram of the flow, near the top.}}
```

## Phase / Step Details

<!-- Walk the steps. For each: what runs, what it reads/writes, what it emits. -->

### {{Step}}

{{Description, with a `code_ref:line` pointer where helpful.}}

## Boundaries & Guarantees

<!-- What this flow guarantees, and who is allowed to call what. -->

- {{guarantee / boundary}}

## Related

- {{[Related page](../section/page.md)}}
