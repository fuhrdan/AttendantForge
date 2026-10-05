# Changelog

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
