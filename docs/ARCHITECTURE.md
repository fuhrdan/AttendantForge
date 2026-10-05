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
             |                   +-- xref/EOF signals
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

## PDF v0.4 model

The PDF analyzer estimates pressure from five classes of signals:

1. **Cardinality** — object and stream counts.
2. **Amplification declarations** — numeric `/Length` declarations relative to stored file size.
3. **Rendering allocation** — declared image width × height, with a simple 4-byte-per-pixel memory estimate.
4. **Decoder complexity** — filter declarations and chain length.
5. **Structural complexity** — dictionary/array depth, embedded files, and structural marker consistency.

These signals are intentionally conservative heuristics. They are suitable for preflight decisions such as allow, warn, quarantine, or submit to a separately constrained sandbox; they are not a full PDF conformance proof.
