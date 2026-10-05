# Architecture

AttendantForge separates **format recognition**, **bounded static analysis**,
**risk scoring**, and **deployment policy**.

```text
                 untrusted file
                       |
                       v
                signature probe
                       |
             +---------+---------+
             |                   |
             v                   v
          ZIP analyzer        PDF analyzer
             |                   |
             |                   +-- objects / streams
             |                   +-- filters / images
             |                   +-- references
             |                   +-- classic xref
             |                   +-- xref streams
             |                   +-- object streams
             |                   +-- incremental updates
             |
             +-- central directory
             +-- expansion ratios
             +-- ZIP64 metadata
             +-- nesting/path checks
             |
             +---------+---------+
                       |
                       v
                 0..100 risk score
                       |
                       v
              +-------------------+
              | policy layer      |
              | profile/config/CLI|
              +---------+---------+
                        |
                 ALLOW/WARN/BLOCK
```

## Bounded-reader principle

The scanner should not casually perform the expensive operation it is warning
about. ZIP analysis relies on central-directory metadata and bounded signature
inspection of stored nested members. PDF analysis reads at most a 64 MiB prefix,
does not render pages, and does not inflate stream payloads.

## PDF v0.6 model

The PDF analyzer inventories resource-cost and structural signals including:

1. object and stream cardinality;
2. declared stream-length amplification;
3. image dimensions and estimated RGBA allocation;
4. filter-chain complexity;
5. dictionary/array depth and embedded-file markers;
6. indirect references and bounded unresolved-reference checks;
7. classic xref sections;
8. `/Type /XRef` xref streams;
9. `/Type /ObjStm` object streams;
10. `/XRefStm` hybrid-reference markers and `/Prev` incremental-update chains.

`startxref` is considered structurally recognized when it points either to a
classic `xref` table or to an indirect object identified as an xref stream.
This is still a preflight heuristic, not a full PDF conformance checker.

## Policy layer

The risk engine is intentionally independent of deployment thresholds:

```text
static analyzers -> 0..100 score -> policy -> ALLOW / WARN / BLOCK
                                      |
                        defaults/profile/file/CLI
```

The ordering is deterministic:

```text
built-in defaults
      ↓
named profile
      ↓
policy file
      ↓
explicit CLI overrides
```

This lets one binary serve desktop inspection, public upload services, and
higher-security environments without rewriting format heuristics.

## v0.7 constrained probe

The optional dynamic path adds a process boundary after static analysis:

```text
untrusted file
    |
    +--> bounded static scan --> predicted resource budget
    |
    +--> opt-in probe
            |
            v
      constrained child process
      + memory ceiling
      + CPU ceiling
      + wall-clock ceiling
      + no temp-file creation
            |
            v
      AttendantForge parser only
            |
            v
      measured peak RAM / CPU / elapsed
            |
      +-----+-------------------+
      |                         |
   completes                 limit hit
      |                         |
 policy score              fail-closed BLOCK
```

The worker is intentionally not a generic command runner. This avoids turning a
preflight scanner into a launcher for potentially vulnerable desktop handlers.
