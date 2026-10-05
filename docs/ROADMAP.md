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

## v0.6 — Policy + modern PDF structures (current)
- external policy files
- `desktop`, `upload-server`, and `high-security` profiles
- xref-stream and object-stream awareness
- incremental-update inventory
- upload-gateway integration example

## v0.7+
- optional OS-constrained dynamic probe with hard CPU/RAM/time quotas
- additional archive/container/image formats
- policy controls for format allowlists and per-format limits
- richer metrics/telemetry output for fleet deployment
