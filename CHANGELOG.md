# Changelog

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
