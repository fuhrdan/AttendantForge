# AttendantForge v0.4.0

**AttendantForge** is a defensive, format-aware file resource-cost assessor. It examines untrusted files *before* another application opens or extracts them and reports whether their declared structure suggests disproportionate CPU, memory, disk, traversal, decompression, or rendering cost.

AttendantForge is **not antivirus**. Its core question is:

> How much work is this file asking the next parser, extractor, or renderer to perform compared with the size of the file I received?

## v0.4 highlights

- C11 CLI suitable for Linux and Windows.
- ZIP central-directory analysis without normal extraction.
- ZIP64 single-disk metadata support.
- ZIP expansion ratios, declared expanded size, entry counts, nested archive candidates, traversal/absolute path checks, and recommended budgets.
- **New PDF static resource analyzer.**
- PDF object and stream inventory.
- PDF filter and `/FlateDecode` inventory.
- Maximum filter-chain heuristic.
- Declared stream-length vs. file-size amplification estimate.
- Image count, declared pixel workload, and estimated RGBA memory pressure.
- Embedded-file detection.
- Dictionary/array structural-depth heuristic.
- `xref`, `startxref`, and EOF consistency signals.
- Unified 0-100 risk score.
- Bounded analysis: PDF stream data is not decoded or rendered, and the static PDF scan is capped at 64 MiB.
- GitHub Actions CI and safe regression fixtures.

## Build

### CMake

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

### Make

```bash
make
make test
```

## Usage

```bash
./attendantforge scan suspicious.zip
./attendantforge scan suspicious.pdf
./attendantforge --version
```

A PDF report includes fields such as:

```text
Objects observed
Streams observed
Filter declarations
FlateDecode filters
Maximum filter chain
Image objects
Embedded-file objects
Declared stream bytes
Declared stream/file ratio
Total declared pixels
Largest declared image
Estimated image memory
Structure depth heuristic
XRef sections observed
startxref / EOF markers
Recommended memory budget
Risk score / level
```

## Safety model

AttendantForge is deliberately **metadata-first and bounded**. It does not recursively inflate arbitrary ZIP members, decode PDF streams, execute embedded content, or render PDF pages during a normal `scan`. This reduces the chance that the defensive scanner becomes the resource-exhaustion victim.

The PDF numbers are **resource-pressure estimates**, not promises that a particular viewer will allocate an exact number of bytes. Different PDF engines can have different caches, decoding strategies, and render pipelines.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the ZIP-bomb and PDF-exhaustion mechanisms AttendantForge is designed to defend against.

## Project status

v0.4 introduces the first PDF cost model while retaining all v0.3 ZIP checks. Planned work includes richer PDF cross-reference/reference-graph analysis, JSON output, policy files, and an optional OS-constrained dynamic probe.

## License

MIT. See [`LICENSE`](LICENSE).
