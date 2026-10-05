# Architecture

```text
                    ATTENDANTFORGE
                          |
                   +------+------+
                   | File Probe  |
                   +------+------+
                          |
                    signature + size
                          |
                          v
                    FORMAT ROUTER
                          |
                 +--------+--------+
                 |                 |
                ZIP               PDF
              (v0.2+)           (v0.4+)
                 |                 |
                 +--------+--------+
                          |
                          v
                   RESOURCE MODEL
                          |
                +---------+---------+
                |         |         |
               RAM       CPU       DISK
                |         |         |
                +---------+---------+
                          |
                          v
                     RISK ENGINE
                          |
                          v
                  LOW / MED / HIGH
```

## v0.1 responsibilities

Version 0.1 intentionally establishes only the safe foundation:

1. CLI command surface.
2. File signature recognition for ZIP and PDF.
3. Common report structure.
4. Common 0-100 risk score and severity mapping.
5. Coarse input-size checks.
6. Unit tests and CI.
7. Threat-model documentation.

Format-specific decompression and object-graph analysis are deliberately separated into later milestones.
