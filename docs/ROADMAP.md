# Roadmap

## v0.1 - Foundation — complete
- CLI scanner
- ZIP/PDF signature detection
- common risk model
- tests and CI
- defensive threat-model documentation

## v0.2 - ZIP metadata analyzer — complete
- End of Central Directory discovery
- central-directory parsing and bounds checks
- entry count
- compressed/uncompressed totals
- per-entry and aggregate expansion ratios
- ZIP-specific scoring
- bounded metadata-only regression fixtures

## v0.3 - ZIP resource analysis
- bounded nested-archive inspection
- recursion accounting
- path anomaly detection
- extraction budget recommendations
- ZIP64 accounting

## v0.4 - PDF structure analyzer
- header/version
- indirect object enumeration
- xref/trailer discovery
- stream/filter inventory

## v0.5 - PDF stream analysis
- bounded stream decoding
- decoded-byte accounting
- filter-chain scoring

## v0.6 - PDF render-cost heuristics
- image dimensions and pixel budget
- structural depth
- repeated resource references
- embedded content inventory

## v0.7 - Unified scoring
- disk, memory, CPU, and structural pressure dimensions
- weighted risk score

## v0.8 - Machine-readable output
- JSON output
- stable exit codes
- integration API

## v0.9 - Test corpus and CI hardening
- bounded adversarial fixtures
- fuzz harness
- regression corpus

## v1.0
- polished Windows/Linux CLI
- documentation and examples
- stable scoring semantics
