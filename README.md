# AttendantForge v1.0.0

**AttendantForge** is a defensive, format-aware file resource-cost assessor. It
preflights untrusted files before another application extracts, decodes,
renders, or otherwise processes them.

AttendantForge is **not antivirus**. Its primary question is:

> How much work is this file asking the next parser to perform relative to the
> file that was received?

## 1.0 stable release

v1.0 freezes AttendantForge's first stable operational contract:

- commands: `scan`, `probe`, and `batch`
- exit codes: `0`, `10`, `20`, `2`, and `3`
- policy precedence: defaults → profile → policy file → CLI overrides
- detected types: ZIP, PDF, GZIP, TAR, PNG, JPEG, UNKNOWN
- telemetry schema: `1.0`
- CLI contract: `1.0`

The release also adds CMake installation rules, versioned audit telemetry,
release-hygiene tooling, a documented compatibility/support policy, and
Linux/Windows/macOS CI.

## Supported resource-cost analyzers

- **ZIP** — central-directory expansion accounting, ZIP64, nested candidates,
  path traversal/rooted-path checks, extraction budgets
- **PDF** — bounded object/stream/filter/image/xref/object-stream analysis and
  estimated memory pressure without rendering or stream inflation
- **GZIP** — header/trailer inspection and declared expansion-ratio estimation
- **TAR** — bounded entry accounting, declared content size, traversal/rooted
  path checks without extraction
- **PNG** — IHDR dimensions, pixel count, estimated decoded-memory cost
- **JPEG** — bounded marker traversal, frame dimensions, pixel count, estimated
  decoded-memory cost

## Build and test

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Or on POSIX-like systems:

```bash
make
make test
```

Install to a staging prefix with:

```bash
cmake --install build --prefix ./stage --config Release
```

## Static scans

```bash
attendantforge scan suspicious.zip
attendantforge scan --json suspicious.pdf
attendantforge scan --profile upload-server archive.tar
attendantforge scan --policy config/high-security.conf oversized.png
```

## Constrained probe

```bash
attendantforge probe --json suspicious.pdf
attendantforge probe --memory-mib 128 --cpu-seconds 1 --timeout-ms 1500 upload.zip
```

The probe executes **AttendantForge's own bounded parser** in an isolated worker.
It does not launch Acrobat, image viewers, system archive extractors, shells, or
arbitrary external programs.

## Batch/quarantine scanning

```bash
attendantforge batch --recursive --profile upload-server ./quarantine
attendantforge batch --recursive --ndjson results.ndjson ./quarantine
attendantforge batch --csv results.csv ./downloads
```

Batch scanning avoids following POSIX symlinks and Windows reparse points.
Recognized filename-extension/signature mismatches are reported separately from
the detected type, and allow/deny policy is applied to the **detected bytes**, not
the filename.

## Profiles

| Profile | Warn | Block | Max GZIP ratio | Max TAR entries | Max image pixels |
|---|---:|---:|---:|---:|---:|
| `desktop` | 60 | 80 | 500x | 100,000 | 250,000,000 |
| `upload-server` | 45 | 70 | 250x | 50,000 | 150,000,000 |
| `high-security` | 30 | 60 | 100x | 10,000 | 80,000,000 |

Per-format ceilings and explicit allow/deny rules can produce `BLOCK` even if a
file's generic risk score is below the normal block threshold.

## Stable process decisions

| Exit | Meaning |
|---:|---|
| `0` | ALLOW |
| `10` | WARN / review |
| `20` | BLOCK / quarantine / probe resource limit reached |
| `2` | invalid CLI or policy |
| `3` | scan/probe infrastructure failure |

## Telemetry

Single-file JSON contains `telemetry_schema: "1.0"` and
`cli_contract: "1.0"`. Batch NDJSON/CSV records carry schema version `1.0` as
well. See [`docs/AUDIT_TELEMETRY.md`](docs/AUDIT_TELEMETRY.md).

## Documentation

- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — ZIP bomb, PDF exhaustion, and generalized resource amplification
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — architecture and trust boundaries
- [`docs/API_CONTRACT.md`](docs/API_CONTRACT.md) — stable 1.0 CLI/exit-code/telemetry contract
- [`docs/POLICY.md`](docs/POLICY.md) — profiles, policy files, and format ceilings
- [`docs/PROBE.md`](docs/PROBE.md) — isolated parser probe
- [`docs/INTEGRATION.md`](docs/INTEGRATION.md) — upload/download gateway pattern
- [`docs/FORMATS.md`](docs/FORMATS.md) — format-specific resource model
- [`docs/BATCH.md`](docs/BATCH.md) — directory scanning and telemetry
- [`docs/AUDIT_TELEMETRY.md`](docs/AUDIT_TELEMETRY.md) — audit/SIEM output guidance
- [`docs/RELEASE.md`](docs/RELEASE.md) — build, install, and release procedure
- [`docs/SUPPORT.md`](docs/SUPPORT.md) — compatibility and support scope

## Safety scope

AttendantForge estimates **resource pressure**, not malicious intent. An ALLOW
result is not proof that a file is benign. Production systems should combine it
with hardened parsers, process/OS quotas, malware scanning where appropriate,
and non-executable quarantine storage.

The repository's bounded fixtures model dangerous *metadata characteristics*
without shipping a destructive archive or document intended to exhaust a host.

## License

MIT. See [`LICENSE`](LICENSE).
