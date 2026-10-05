# Audit Telemetry

AttendantForge telemetry is designed for admission logs, quarantine pipelines,
SIEM ingestion, and reproducible policy decisions. It reports what the scanner
observed and which policy decision followed; it does not claim that a file is
malware.

## Single-file JSON

`scan --json` and `probe --json` include:

- tool version
- telemetry schema version
- CLI contract version
- path and detected format
- byte size
- extension/signature mismatch flag
- risk score and band
- effective policy/profile and decision
- format-specific resource metrics
- optional constrained-probe measurements
- analyst notes

## Batch NDJSON

Each line is an independent JSON object and starts with `schema_version: "1.0"`.
This makes partial logs useful even if a long-running batch job is interrupted.

## Batch CSV

The first column is `schema_version`; all string fields are quoted where needed.

## Operational guidance

Treat paths and filenames as potentially sensitive. If telemetry is exported to
a central service, apply the same retention and access controls used for other
security logs. Do not treat ALLOW as proof of safety; AttendantForge is a
resource-cost admission layer and complements malware scanners and hardened
parsers.
