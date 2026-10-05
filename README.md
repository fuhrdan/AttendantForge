# AttendantForge v0.8.0

**AttendantForge** is a defensive, format-aware file resource-cost assessor. It
preflights untrusted files before another application extracts, decodes,
renders, or otherwise processes them.

AttendantForge is **not antivirus**. Its primary question is:

> How much work is this file asking the next parser to perform relative to the
> file that was received?

## v0.8 highlights

v0.8 turns AttendantForge from a ZIP/PDF specialist into the beginning of a
**general-purpose file admission firewall**.

Supported static analyzers now include:

- ZIP — central-directory expansion accounting, ZIP64, nested candidates, path safety
- PDF — bounded structural/stream/image/xref/object-stream analysis
- GZIP — header/trailer inspection and declared expansion-ratio estimation
- TAR — bounded entry accounting, declared content size, path traversal/rooted paths
- PNG — IHDR dimensions, pixel count, estimated decoded-memory cost
- JPEG — bounded marker walk, frame dimensions, pixel count, estimated decoded-memory cost

The opt-in v0.7 constrained `probe` remains available for all supported formats.

## Build

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

or:

```bash
make
make test
```

## Scan examples

```bash
./attendantforge scan suspicious.zip
./attendantforge scan --json suspicious.pdf
./attendantforge scan archive.tar
./attendantforge scan compressed.gz
./attendantforge scan oversized.png
./attendantforge scan photo.jpg
```

## Constrained probe

```bash
./attendantforge probe --json suspicious.pdf
./attendantforge probe --memory-mib 128 --cpu-seconds 1 --timeout-ms 1500 upload.zip
```

The probe executes AttendantForge's own bounded parser in an isolated worker. It
does **not** launch Acrobat, image viewers, archive extractors, shells, or arbitrary
external programs.

## Policy profiles and per-format ceilings

| Profile | Warn | Block | Max GZIP ratio | Max TAR entries | Max image pixels |
|---|---:|---:|---:|---:|---:|
| `desktop` | 60 | 80 | 500x | 100,000 | 250,000,000 |
| `upload-server` | 45 | 70 | 250x | 50,000 | 150,000,000 |
| `high-security` | 30 | 60 | 100x | 10,000 | 80,000,000 |

A format ceiling is an explicit admission rule: exceeding it produces `BLOCK`
even when the generic risk score has not yet reached the global block threshold.

Policy files can set:

```text
max_gzip_ratio=250
max_tar_entries=50000
max_image_pixels=150000000
```

Policy precedence remains:

```text
defaults -> named profile -> policy file -> explicit CLI overrides
```

## Stable process decisions

- `0` — ALLOW
- `10` — WARN / review
- `20` — BLOCK / quarantine / probe resource limit reached
- `2` — invalid CLI or policy
- `3` — scan or probe infrastructure failure

## Why image files are included

A compressed image can be small while requiring a very large decoded pixel
buffer. AttendantForge therefore evaluates dimensions and estimated decoded
memory rather than trusting compressed file size alone. This is the same general
resource-amplification principle used for ZIP, GZIP, and PDF analysis.

## Documentation

- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — ZIP bomb, PDF exhaustion, and resource-amplification model
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — scanner architecture
- [`docs/POLICY.md`](docs/POLICY.md) — profiles, external policy files, and format ceilings
- [`docs/PROBE.md`](docs/PROBE.md) — isolated parser probe
- [`docs/INTEGRATION.md`](docs/INTEGRATION.md) — upload/download gateway pattern
- [`docs/FORMATS.md`](docs/FORMATS.md) — v0.8 format-specific cost model

## Safety scope

AttendantForge estimates **resource pressure**, not malicious intent. Static
analysis can be incomplete, especially where formats contain ambiguous,
streamed, externally referenced, or modulo-sized metadata. Production systems
should combine AttendantForge with hardened parsers, OS/process resource limits,
malware scanning where appropriate, and quota-controlled non-executable storage.

## License

MIT. See [`LICENSE`](LICENSE).
