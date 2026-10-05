# Architecture

AttendantForge separates **format recognition**, **bounded static analysis**, and **risk scoring** so additional formats can be added without changing the command-line contract.

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
             |                   +-- object/stream inventory
             |                   +-- filters
             |                   +-- image dimensions
             |                   +-- embedded files
             |                   +-- structural depth
             |                   +-- references/xref/EOF signals
             |
             +-- central directory
             +-- expansion ratios
             +-- ZIP64 metadata
             +-- nesting/path checks
             |
             +---------+---------+
                       |
                       v
                common risk model
                       |
                 LOW / MEDIUM /
                 HIGH / CRITICAL
```

## Bounded-reader principle

The scanner should never casually perform the expensive operation it is warning about.

ZIP analysis therefore relies on central-directory metadata and only performs bounded signature inspection of stored nested members. PDF analysis does not inflate streams or render pages. It scans at most the first 64 MiB and skips stream payload bytes while inventorying surrounding structure.

## PDF v0.5 model

The PDF analyzer estimates pressure from five classes of signals:

1. **Cardinality** — object and stream counts.
2. **Amplification declarations** — numeric `/Length` declarations relative to stored file size.
3. **Rendering allocation** — declared image width × height, with a simple 4-byte-per-pixel memory estimate.
4. **Decoder complexity** — filter declarations and chain length.
5. **Structural complexity** — dictionary/array depth, embedded files, and structural marker consistency.

These signals are intentionally conservative heuristics. v0.5 also inventories indirect references, estimates unresolved references within the bounded scan, validates that `startxref` is in range, and—when classic xref tables are present—checks whether the offset points at one. These checks are suitable for preflight decisions such as allow, warn, quarantine, or submit to a separately constrained sandbox; they are not a full PDF conformance proof.

## Policy layer

The CLI maps the common risk score onto an explicit pipeline decision:

```text
static analyzer -> 0..100 score -> policy thresholds -> ALLOW / WARN / BLOCK
                                            |             |      |
                                            +---------- exit 0 / 10 / 20
```

The policy layer is intentionally separate from format parsing so callers can tighten thresholds without changing the ZIP/PDF heuristics.
