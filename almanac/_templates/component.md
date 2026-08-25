---
title: {{Component Name}}
topics:
  - components
  - {{domain-topic}}
sources:
  - id: {{slug}}
    type: file
    path: {{path/to/source}}
    note: {{the primary file}}
---

# {{Component Name}}

{{One paragraph: what this component does and what it owns.}}

## Interface / Contract

<!-- The public surface: what other code depends on. Signatures, not full impl. -->

```{{lang}}
{{key type / interface / entry function signatures}}
```

## Internals

{{How it works inside — the parts a maintainer needs, not a line-by-line copy of
the code. Focus on non-obvious behavior, invariants it maintains, and edge cases.}}

## Inputs & Outputs

- **Consumes:** {{types / events / files}}
- **Produces:** {{types / events / files}}

## Gotchas

- {{Non-obvious behavior a future editor will trip over.}}

## Related

- {{[Related page](../section/page.md)}}
