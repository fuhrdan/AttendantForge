# Roadmap

## v0.1 — Foundation
- CLI, signature detection, common risk levels

## v0.2 — ZIP metadata cost model
- central-directory parsing, expansion ratios, entry-count scoring

## v0.3 — Container hardening
- ZIP64 accounting, nested candidates, path safety, recommended budgets

## v0.4 — PDF structural analyzer
- bounded PDF object/stream/filter/image/resource-cost analysis

## v0.5 — Pipeline integration
- JSON output, stable exit codes, configurable thresholds, strict mode
- indirect-reference inventory and classic `startxref` validation

## v0.6 — Policy + modern PDF structures
- external policy files and named profiles
- xref/object-stream and incremental-update awareness
- upload-gateway integration example

## v0.7 — Constrained dynamic probe (current)
- opt-in isolated AttendantForge parser worker
- hard memory/CPU/elapsed-time ceilings
- Linux/Unix rlimits and Windows Job Objects
- measured-vs-predicted parser resource reporting
- fail-closed limit/timeout behavior

## v0.8+
- additional archive/container/image formats
- per-format policy controls and allowlists
- richer metrics/telemetry output for fleet deployment
- optional disposable-sandbox adapters for selected external parsers/renderers
