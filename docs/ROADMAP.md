# AttendantForge Roadmap

## v1.0.0 — Stable baseline (complete)

- ZIP/PDF/GZIP/TAR/PNG/JPEG metadata-first analyzers
- resource-risk scoring and named policy profiles
- external policy files and explicit format admission rules
- bounded isolated parser probe
- recursive batch/quarantine scanning
- extension/signature mismatch detection
- JSON, NDJSON, and CSV telemetry
- stable CLI/exit-code contract and telemetry schema 1.0
- Linux/Windows/macOS CI and CMake install support

## 1.x candidates

- richer ZIP nested-container accounting without uncontrolled expansion
- optional cryptographic file identity in audit records
- additional metadata-first formats where cost can be estimated safely
- service/daemon wrapper for local admission gateways
- signed release artifacts and package-manager recipes
- larger cross-parser regression corpus built from bounded fixtures

## 2.0 candidates

Reserved for changes that require a deliberate compatibility break to the 1.0
CLI, exit-code, policy-precedence, or telemetry contracts.
