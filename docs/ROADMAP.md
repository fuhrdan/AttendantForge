# Roadmap

## v0.1 — Foundation
- CLI
- signature detection
- common risk levels

## v0.2 — ZIP metadata cost model
- central-directory parsing
- expansion ratios
- declared expanded size
- entry-count scoring

## v0.3 — Container hardening
- ZIP64 single-disk accounting
- nested archive candidate detection
- bounded stored-nested ZIP confirmation
- parent traversal and absolute-path detection
- recommended disk / memory budgets
- expanded regression tests

## v0.4 — PDF structural analyzer (current)
- bounded static PDF scan
- object and stream inventory
- filter and FlateDecode inventory
- filter-chain heuristic
- declared stream-length amplification signal
- image dimensions / pixel-cost estimate
- embedded-file detection
- dictionary/array depth heuristic
- xref/startxref/EOF signals
- PDF-specific 0-100 resource-risk scoring

## v0.5
- JSON output
- machine-readable exit codes/policy thresholds
- richer indirect-reference and cross-reference validation
- improved stream ownership accounting

## v0.6+
- policy files
- optional sandbox probe with OS-enforced CPU/RAM/disk limits
- additional container/image formats
- integration helpers for upload/download pipelines
