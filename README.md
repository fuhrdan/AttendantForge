# AttendantForge v0.6.0

**AttendantForge** is a defensive, format-aware file resource-cost assessor. It
preflights untrusted ZIP and PDF files before another application extracts,
decodes, renders, or otherwise processes them.

AttendantForge is **not antivirus**. Its primary question is:

> How much work is this file asking the next parser to perform relative to the
> file that was received?

## v0.6 highlights

- All v0.5 ZIP/PDF bounded static resource analysis and stable pipeline exit codes.
- External `key=value` policy files via `--policy FILE`.
- Built-in `desktop`, `upload-server`, and `high-security` profiles.
- Deterministic policy precedence: defaults → profile → policy file → CLI overrides.
- PDF 1.5+ xref-stream recognition.
- PDF `/ObjStm`, `/XRefStm`, and `/Prev` inventory for object streams, hybrid xref
  references, and incremental-update chains.
- `startxref` can now resolve to either a classic xref table or a recognized
  xref-stream object.
- JSON output reports the effective profile and policy source.
- Standard-library Python upload-gateway example in `examples/upload-gateway/`.
- Bounded parsing only: no arbitrary ZIP inflation, PDF stream decoding,
  embedded execution, or page rendering.

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

## Usage

```bash
./attendantforge scan suspicious.zip
./attendantforge scan suspicious.pdf
./attendantforge scan --json suspicious.pdf
./attendantforge scan --profile upload-server upload.zip
./attendantforge scan --policy config/attendantforge.conf.example upload.pdf
./attendantforge scan --profile high-security --json upload.pdf
```

Explicit thresholds are still supported:

```bash
./attendantforge scan --warn-score 40 --block-score 70 upload.pdf
```

## Policy profiles

| Profile | Warn | Block | Strict | Typical use |
|---|---:|---:|---|---|
| `desktop` | 60 | 80 | no | interactive/local inspection |
| `upload-server` | 45 | 70 | no | public upload/download pipelines |
| `high-security` | 30 | 60 | yes | highly untrusted submissions |

See [`docs/POLICY.md`](docs/POLICY.md) for configuration syntax and precedence.

## Stable process decisions

- `0` — ALLOW
- `10` — WARN / review
- `20` — BLOCK / quarantine
- `2` — invalid CLI or policy
- `3` — scan failure

Example:

```bash
attendantforge scan --json --policy config/attendantforge.conf.example "$UPLOAD"
case $? in
  0)  echo "allow" ;;
  10) echo "warn/review" ;;
  20) echo "block" ;;
  *)  echo "scanner error; fail closed" ;;
esac
```

## Defensive model

ZIP analysis is metadata-first and does not normally inflate compressed members.
PDF analysis is bounded to a 64 MiB static prefix, skips stream decoding and page
rendering, and uses declared resource costs plus structural signals. Modern PDFs
that use xref streams and object streams are recognized rather than treated as
classic-xref failures.

See:

- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — ZIP bomb and PDF exhaustion model
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — scanner architecture
- [`docs/POLICY.md`](docs/POLICY.md) — external policy files and profiles
- [`docs/INTEGRATION.md`](docs/INTEGRATION.md) — upload/download gateway pattern

## Safety scope

AttendantForge estimates **resource pressure**, not malicious intent, and does
not guarantee that a file is safe. A production system should combine it with
hardened parsers, OS/process limits, malware scanning where appropriate, and
non-executable/quota-controlled temporary storage.

## License

MIT. See [`LICENSE`](LICENSE).
