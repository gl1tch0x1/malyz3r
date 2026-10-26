# Architecture diagrams

The six numbered Mermaid sources preserve the original workbench diagrams, in order:
architecture, analyst workflow, run sequence, terminal states, metric computation,
and revision comparison. Corresponding SVG files were rendered with Mermaid CLI
11.13.0 and visually inspected on 23 October 2026.

The current root README includes additional architecture diagrams. These numbered
sources remain the canonical inputs for their corresponding SVG files. With Mermaid CLI installed, render an individual diagram with:

```console
mmdc -i docs/diagrams/01.mmd -o docs/diagrams/01.svg
```

Rendering is a documentation task; the scanner does not depend on Node.js or Mermaid.
