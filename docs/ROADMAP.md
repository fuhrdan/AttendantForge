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

## v0.6 — Policy + modern PDF structures
- external policies/profiles, xref/object streams, upload-gateway example

## v0.7 — Constrained dynamic probe
- isolated parser worker with hard RAM/CPU/elapsed-time ceilings

## v0.8 — General file-admission formats
- metadata-first GZIP and TAR analyzers
- PNG and JPEG decoded-pixel/memory estimators
- per-format admission ceilings in policy profiles/files
- unified JSON/text reporting and regression fixtures

## v0.9 — Operational scanning (current)
- recursive batch/directory scanning
- NDJSON and CSV telemetry
- extension/signature mismatch detection
- explicit format allow/deny policy controls
- aggregate quarantine-directory summaries and strongest-result exit behavior

## v1.0+
- richer telemetry and audit integration
- additional containers/images where metadata-first analysis is reliable
- optional disposable-sandbox adapters for selected external parsers/renderers
