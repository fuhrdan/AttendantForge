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

## v0.3 — Container hardening (current)
- ZIP64 single-disk accounting
- nested archive candidate detection
- bounded stored-nested ZIP confirmation
- parent traversal and absolute-path detection
- recommended disk / memory budgets
- expanded regression tests

## v0.4 — PDF structural analyzer
- header/version and EOF consistency
- xref/object enumeration
- stream/filter-chain inventory
- image dimensions and pixel-cost estimates
- object/reference depth heuristics

## v0.5+
- JSON output
- policy files
- optional sandbox probe with OS-enforced CPU/RAM/disk limits
- additional container/image formats
