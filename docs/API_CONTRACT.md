# AttendantForge 1.0 CLI and API Contract

AttendantForge 1.0 freezes the command-line behavior used by upload gateways,
quarantine jobs, CI, and local inspection tooling.

## Commands

- `attendantforge scan [options] <file>` — static metadata-first assessment.
- `attendantforge probe [options] <file>` — static assessment plus isolated bounded parser worker.
- `attendantforge batch [options] <directory>` — directory admission/quarantine scanning.
- `attendantforge --version` — semantic release version.

Future 1.x releases may add commands and output fields, but will not intentionally
remove or reinterpret these commands without a deprecation period.

## Process exit codes

| Code | Stable meaning |
|---:|---|
| 0 | ALLOW |
| 10 | WARN / manual review |
| 20 | BLOCK / quarantine / probe limit hit |
| 2 | CLI or policy configuration error |
| 3 | scan/probe infrastructure failure |

## Risk bands

- 0–29: LOW
- 30–59: MEDIUM
- 60–79: HIGH
- 80–100: CRITICAL

Policy thresholds are independent of those display bands. Explicit per-format
ceilings and allow/deny rules can block a file even if its generic score is lower.

## Policy precedence

`built-in defaults -> named profile -> policy file -> CLI overrides`

This precedence is part of the 1.0 contract.

## Supported detected formats

`ZIP`, `PDF`, `GZIP`, `TAR`, `PNG`, `JPEG`, and `UNKNOWN`.

The detected signature controls format policy. A misleading extension is reported
separately and does not change the detected type.

## Telemetry compatibility

Single-scan JSON declares both `telemetry_schema` and `cli_contract` as `1.0`.
Batch NDJSON/CSV declares `schema_version=1.0`. Within telemetry schema 1.x,
consumers should ignore unknown fields so AttendantForge can add non-breaking
observations in future releases.
