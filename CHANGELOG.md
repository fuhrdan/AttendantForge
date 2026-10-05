# Changelog

## 0.9.0

- Added recursive `batch` directory/quarantine scanning.
- Added NDJSON and CSV telemetry output.
- Added extension-versus-signature mismatch detection.
- Added `allow_formats` and `deny_formats` admission policy controls.
- Added aggregate batch summary counters and strongest-result exit behavior.
- Added `docs/BATCH.md`.

## v0.8.0

### Added
- Metadata-first GZIP analyzer using header/trailer information and expansion-ratio estimates.
- Bounded TAR header walker with entry counts, declared sizes, link/path safety signals, and malformed-header detection.
- PNG IHDR analyzer with decoded pixel/memory estimation.
- JPEG marker/SOF analyzer with decoded pixel/memory estimation.
- Per-format policy ceilings: `max_gzip_ratio`, `max_tar_entries`, and `max_image_pixels`.
- Format-ceiling enforcement that can block independently of the generic risk score.
- JSON/text metrics for GZIP, TAR, PNG, and JPEG.
- `docs/FORMATS.md` and bounded regression fixtures for each new format.

### Changed
- Version updated to 0.8.0 across builds, CLI output, tests, and documentation.
- AttendantForge now describes itself as a general-purpose file resource-cost admission layer rather than only a ZIP/PDF assessor.

### Safety
- GZIP content is not inflated during static analysis.
- TAR payloads are skipped rather than copied/extracted.
- PNG IDAT and JPEG entropy-coded image data are not decoded.
- Existing constrained probe continues to run only AttendantForge's own parsers.


## v0.7.0

### Added
- Opt-in `probe` command using an isolated AttendantForge parser worker.
- Configurable `--memory-mib`, `--cpu-seconds`, and `--timeout-ms` ceilings.
- Linux/Unix address-space and CPU rlimits with parent wall-clock enforcement.
- Windows Job Object process-memory and CPU limits with parent wall-clock enforcement.
- Peak-memory, CPU-time, elapsed-time, predicted-memory, and measured/predicted reporting.
- JSON `probe` object for machine-readable automation.
- `docs/PROBE.md` documenting the isolation model and safety boundary.

### Changed
- Exit code `20` also represents a dynamic-probe resource limit or timeout.
- Version updated to 0.7.0 across builds, CLI output, tests, and documentation.

### Safety
- The dynamic worker executes only AttendantForge's bounded parsers. It does not
  launch arbitrary viewers/extractors, render PDFs, inflate arbitrary nested ZIP
  members, execute document actions, or open embedded content.

## v0.6.0

### Added
- External `key=value` policy files with strict validation.
- Named `desktop`, `upload-server`, and `high-security` policy profiles.
- Deterministic policy precedence: defaults → profile → policy file → CLI overrides.
- PDF xref-stream recognition for `startxref` targets.
- `/ObjStm`, `/XRefStm`, and `/Prev` inventory.
- JSON policy metadata including effective profile and policy-file source.
- Upload-gateway integration example using safe subprocess invocation, JSON, a
  caller-side timeout, and stable AttendantForge exit codes.
- Policy and integration documentation plus example configuration files.

### Changed
- Modern PDFs using xref streams are no longer treated as classic-xref failures
  solely because `startxref` targets an indirect xref-stream object.
- PDF scoring can flag unusually large object-stream or incremental-update counts.
- Version updated to 0.6.0 across builds, CLI output, tests, and documentation.

### Safety
- ZIP nested inspection remains bounded and does not inflate arbitrary compressed
  members.
- PDF scanning remains a static bounded-prefix analysis and does not decode
  streams or render pages.

## v0.5.0
- Added JSON reports for automation and upload pipelines.
- Added stable exit codes for allow/warn/block and scanner failures.
- Added configurable warning/block thresholds and strict policy mode.
- Added PDF indirect-reference and unresolved-reference accounting.
- Added `startxref` range and classic-xref target validation.

## v0.4.0
- Added bounded PDF static resource analysis and PDF-specific scoring.

## v0.3.0
- Added ZIP64 accounting, nested archive indicators, path safety checks, and
  recommended processing budgets.

## v0.2.0
- Added ZIP central-directory analysis and expansion-ratio scoring.

## v0.1.0
- Initial CLI, file identification, and shared risk model.
