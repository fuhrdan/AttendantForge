# AttendantForge v0.5.0

**AttendantForge** is a defensive, format-aware file resource-cost assessor. It examines untrusted ZIP and PDF files before another application extracts, renders, or otherwise processes them.

AttendantForge is not antivirus. Its primary question is: **how much work is this file asking the next parser to perform relative to the file received?**

## v0.5 highlights

- All v0.4 ZIP/PDF static resource analysis.
- `--json` machine-readable output for upload/download pipelines.
- Stable policy exit codes: `0` allow, `10` warn, `20` block, `2` usage error, `3` scan error.
- Configurable `--warn-score N` and `--block-score N` thresholds.
- `--strict` policy mode; unless overridden, HIGH risk (`>=60`) blocks.
- PDF indirect-reference inventory and unresolved-reference heuristics.
- `startxref` offset range validation and classic-xref target validation.
- Bounded parsing only: no arbitrary ZIP inflation, PDF stream decoding, embedded execution, or page rendering.

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
./attendantforge scan --strict upload.zip
./attendantforge scan --warn-score 40 --block-score 70 upload.pdf
```

Example pipeline usage:

```bash
attendantforge scan --json --strict "$UPLOAD"
case $? in
  0)  echo "allow" ;;
  10) echo "warn/review" ;;
  20) echo "block" ;;
  *)  echo "scanner error" ;;
esac
```

## Policy semantics

Default policy is `WARN >= 60` and `BLOCK >= 80`. `--strict` changes the default block threshold to 60. Explicit `--block-score` always wins. A warning threshold may not exceed the block threshold.

Risk scoring is heuristic, not a malware verdict. A high score means the file asks for unusual or disproportionate processing resources or contains structural conditions worth isolating.

## Defensive model

ZIP analysis is metadata-first and does not normally inflate compressed members. PDF analysis is bounded to a 64 MiB static prefix, skips rendering/stream decoding, and treats resource declarations and structural inconsistencies as signals. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## License

MIT. See [`LICENSE`](LICENSE).
