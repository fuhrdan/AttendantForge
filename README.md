# AttendantForge v0.7.0

**AttendantForge** is a defensive, format-aware file resource-cost assessor. It
preflights untrusted ZIP and PDF files before another application extracts,
decodes, renders, or otherwise processes them.

AttendantForge is **not antivirus**. Its primary question is:

> How much work is this file asking the next parser to perform relative to the
> file that was received?

## v0.7 highlights

- Everything from v0.6: bounded ZIP/PDF analysis, policy profiles/files, JSON,
  stable pipeline exit codes, and modern PDF xref/object-stream awareness.
- New opt-in `probe` command that runs AttendantForge's parser in an isolated
  helper process.
- Hard probe ceilings for memory, CPU time, and elapsed time.
- Linux/Unix rlimit enforcement and Windows Job Object enforcement.
- Measured peak memory, CPU time, elapsed time, and predicted-vs-measured memory
  reporting.
- A probe limit hit or timeout fails closed with exit code `20`.
- The worker creates no temporary files and never launches a PDF viewer, ZIP
  extractor, shell payload, or arbitrary external command.

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

## Static scan

```bash
./attendantforge scan suspicious.zip
./attendantforge scan --json suspicious.pdf
./attendantforge scan --profile upload-server upload.zip
./attendantforge scan --policy config/attendantforge.conf.example upload.pdf
```

## Constrained probe

```bash
./attendantforge probe suspicious.pdf
./attendantforge probe --json suspicious.zip
./attendantforge probe --memory-mib 128 --cpu-seconds 1 --timeout-ms 1500 upload.pdf
```

Default probe limits are 256 MiB memory, 2 CPU seconds, and 3000 ms elapsed time.
See [`docs/PROBE.md`](docs/PROBE.md).

## Policy profiles

| Profile | Warn | Block | Strict | Typical use |
|---|---:|---:|---|---|
| `desktop` | 60 | 80 | no | interactive/local inspection |
| `upload-server` | 45 | 70 | no | public upload/download pipelines |
| `high-security` | 30 | 60 | yes | highly untrusted submissions |

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

## Defensive model

ZIP analysis is metadata-first and avoids arbitrary decompression. PDF analysis
uses a bounded static prefix and does not decode streams or render pages. The
v0.7 probe executes only these AttendantForge parsers in a resource-constrained
child process, allowing actual scanner cost to be measured without handing the
file to a general-purpose viewer or extractor.

See:

- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — ZIP bomb and PDF exhaustion model
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — scanner architecture
- [`docs/POLICY.md`](docs/POLICY.md) — external policy files and profiles
- [`docs/PROBE.md`](docs/PROBE.md) — isolated parser probe and resource ceilings
- [`docs/INTEGRATION.md`](docs/INTEGRATION.md) — upload/download gateway pattern

## Safety scope

AttendantForge estimates **resource pressure**, not malicious intent, and does
not guarantee that a file is safe. A production system should combine it with
hardened parsers, OS/process limits, malware scanning where appropriate, and
non-executable/quota-controlled temporary storage.

## License

MIT. See [`LICENSE`](LICENSE).
