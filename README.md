# AttendantForge v0.3.0

**AttendantForge** is a defensive, format-aware file resource-cost assessor. It examines untrusted files *before* another application opens or extracts them and reports whether their declared structure suggests disproportionate CPU, memory, disk, traversal, or parser cost.

AttendantForge is **not antivirus**. Its core question is:

> How much work is this file asking the next parser or extractor to perform compared with the size of the file I received?

## v0.3 highlights

- C11 CLI, suitable for Linux and Windows builds.
- ZIP signature detection and central-directory analysis without normal extraction.
- Aggregate and per-entry expansion ratios.
- Declared expanded-size and entry-count analysis.
- ZIP64 end-record and ZIP64 extra-field accounting for single-disk archives.
- Nested `.zip` candidate detection.
- Bounded confirmation of stored nested ZIP signatures without decoding compressed members.
- `../` / `..\\` traversal detection.
- POSIX-root, UNC/rooted, and Windows drive-path detection.
- Recommended disk and memory processing budgets.
- Unified 0-100 risk score.
- PDF identification remains available; deep PDF analysis is scheduled for v0.4.
- GitHub Actions CI and bounded regression fixtures.

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
./attendantforge scan document.pdf
./attendantforge --version
```

Example ZIP fields include:

```text
Entries
Compressed payload
Declared expanded data
Aggregate ratio
Maximum entry ratio
Nested archive candidates
Traversal paths
Absolute paths
Recommended disk budget
Recommended memory budget
Risk score / level
```

## Safety model

AttendantForge v0.3 is intentionally metadata-first. It does **not** recursively inflate arbitrary compressed archive members. Nested archives that require decompression are reported as candidates instead of being opened. This avoids turning a defensive scanner into the resource consumer it is meant to protect.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the ZIP-bomb and PDF-exhaustion mechanisms AttendantForge is designed to defend against.

## Project status

v0.3 focuses on stronger ZIP/container analysis. v0.4 introduces PDF object, stream, filter, and image/resource-cost analysis.

## License

MIT. See [`LICENSE`](LICENSE).
