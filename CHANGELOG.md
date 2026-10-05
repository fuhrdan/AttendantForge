# Changelog

## 0.4.0

- Added bounded PDF static resource analysis.
- Added PDF object/stream/filter inventory.
- Added FlateDecode and filter-chain heuristics.
- Added declared stream-length amplification signal.
- Added image pixel and estimated image-memory accounting.
- Added embedded-file, structural-depth, xref/startxref/EOF signals.
- Added PDF-specific risk scoring and regression fixtures.
- Preserved v0.3 ZIP/ZIP64, nesting, traversal, and budget checks.

## v0.3.0

### Added
- ZIP64 root metadata and ZIP64 extra-field accounting for single-disk archives.
- Nested `.zip` candidate counting.
- Bounded confirmation of stored nested ZIP signatures without decompression.
- Parent-directory traversal detection (`../` and `..\\`).
- Absolute/rooted extraction-path detection.
- Recommended disk and memory processing budgets.
- Expanded ZIP risk scoring for nesting and path anomalies.
- Regression tests for amplification, nesting, traversal, and absolute paths.

### Safety
- No arbitrary compressed member is decompressed during static analysis.
- Nested inspection is bounded by explicit limits.
- Test fixtures are metadata-oriented and intentionally non-destructive.

## v0.2.0
- Added ZIP central-directory analysis and expansion-ratio scoring.

## v0.1.0
- Initial CLI, file identification, and shared risk model.
