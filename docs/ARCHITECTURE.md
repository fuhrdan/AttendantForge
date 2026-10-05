# Architecture

## v0.2 data flow

```text
file path
   |
   v
signature detection
   |
   +--------------------------+
   |                          |
 ZIP                        PDF/other
   |                          |
   v                          v
EOCD search               coarse scan
   |
   v
central-directory bounds validation
   |
   v
iterate central-directory entries
   |
   +--> compressed size
   +--> declared uncompressed size
   +--> entry count
   +--> ratio metrics
   |
   v
ZIP risk scoring
   |
   v
common AfReport
```

The ZIP analyzer intentionally reads metadata only. It does not invoke a decompressor and does not write extracted data to disk.

## Trust boundaries

All sizes, counts, offsets, and lengths read from an untrusted archive are treated as untrusted. Before seeking or advancing a cursor, AttendantForge checks the values against the physical file size and the declared central-directory bounds.

## Current ZIP64 behavior

ZIP64 uses larger size/count fields and extra records. v0.2 detects sentinel values that indicate ZIP64 and reports the archive as only partially assessed. Full ZIP64 accounting is planned for v0.3.
