# AttendantForge Architecture — v0.3

```text
Untrusted file
     |
     v
+-------------------+
| signature probe   |
+---------+---------+
          |
    +-----+-----+
    |           |
   ZIP         PDF
    |           |
    v           v
central-dir   signature only
analyzer      (v0.4 deep probe)
    |
    +--> entry counts
    +--> compressed / expanded totals
    +--> amplification ratios
    +--> ZIP64 metadata
    +--> path anomalies
    +--> nested archive candidates
    +--> bounded stored-nested confirmation
    |
    v
+-------------------+
| shared risk model |
+---------+---------+
          |
          v
 LOW / MEDIUM / HIGH / CRITICAL
```

## Scanner invariants

1. Do not extract an archive merely to decide whether it is safe to extract.
2. Bound metadata reads and nested inspection.
3. Treat declared sizes as claims, not guarantees.
4. Treat overflow/inconsistent metadata as suspicious.
5. Separate static estimates from future sandbox measurements.
6. Do not write archive members to disk during static analysis.

## v0.3 nested inspection

All `.zip`-named entries are counted as candidates. A stored (method 0) candidate may be cheaply checked for a ZIP local-header signature because no decompression is required. Deflated/encrypted/otherwise encoded nested members are not expanded in v0.3.

This is intentionally conservative: a high-confidence static warning is preferable to causing resource exhaustion inside the scanner.
