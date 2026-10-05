# AttendantForge v1.0.0 Release Notes

AttendantForge 1.0 is the first stable release of the defensive file
resource-cost assessor.

## Stable surface

- `scan`, `probe`, and `batch` commands
- exit codes `0`, `10`, `20`, `2`, and `3`
- ZIP, PDF, GZIP, TAR, PNG, and JPEG detection/analyzers
- named profiles and external policy files
- explicit format allow/deny rules and per-format ceilings
- JSON, NDJSON, and CSV telemetry schema 1.0
- recursive quarantine scanning and extension/signature mismatch detection
- bounded isolated parser probing

## Release engineering

- Linux, Windows, and macOS CI
- warning-enabled C11 builds
- CMake install target
- dependency-free release hygiene script
- compatibility, audit, release, and support documentation

## Safety model

AttendantForge estimates resource pressure without extracting ZIP/TAR members,
inflating GZIP/PDF streams, decoding images, launching document viewers, or
executing arbitrary external handlers. Test fixtures model dangerous metadata
characteristics while remaining bounded.
