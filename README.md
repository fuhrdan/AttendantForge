# AttendantForge

**Pre-open resource-cost analysis for untrusted files.**

AttendantForge is a defensive C utility designed to answer a question traditional malware scanners do not always answer:

> **How much computational work might this file ask the machine to perform compared with how small the file looks?**

Version **0.1.0** establishes the project foundation: a cross-platform CLI, ZIP/PDF signature detection, a common resource-risk model, tests, CI, and documentation describing the resource-exhaustion threats the project is intended to defend against.

> AttendantForge is not an antivirus engine and does not claim a file is malware-free or safe to open.

## Why this exists

Two useful examples are ZIP expansion attacks and PDF resource-exhaustion documents.

A ZIP may be small on disk yet represent a much larger extracted data set. A PDF may be small on disk yet contain compressed streams, large object graphs, image dimensions, nested structures, or rendering instructions that request disproportionate CPU, memory, or disk resources.

AttendantForge treats these as **resource-accounting problems** rather than merely signature-detection problems.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for diagrams and a defensive description of both attack classes.

## v0.1 architecture

```text
untrusted file
      |
      v
signature probe
      |
      v
ZIP / PDF / unknown
      |
      v
common resource-risk report
```

Later releases add format-aware analyzers behind this interface.

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
./build/attendantforge scan suspicious.pdf
./build/attendantforge scan archive.zip
./build/attendantforge --version
```

Example v0.1 output:

```text
AttendantForge v0.1.0

File:        example.pdf
Type:        PDF
Size:        0.42 MiB
Risk score:  0 / 100
Risk level:  LOW
Notes:       Recognized format; deep analysis not enabled in v0.1.

PDF deep analysis begins in v0.4.
```

The low score in v0.1 means only that no coarse v0.1 signal fired. It is **not** a safety verdict.

## Risk levels

| Score | Level |
|---:|---|
| 0-29 | LOW |
| 30-59 | MEDIUM |
| 60-79 | HIGH |
| 80-100 | CRITICAL |

Format-specific scoring begins with the ZIP analyzer in v0.2.

## Safety model

The project intentionally uses bounded fixtures and static analysis. It does not ship generators for destructive ZIP bombs or PDFs intended to consume unbounded resources.

See [`SECURITY.md`](SECURITY.md).

## Repository layout

```text
AttendantForge/
├── .github/workflows/ci.yml
├── docs/
│   ├── ARCHITECTURE.md
│   ├── ROADMAP.md
│   └── THREAT_MODEL.md
├── include/attendantforge.h
├── src/
│   ├── attendantforge.c
│   └── main.c
├── tests/test_main.c
├── CMakeLists.txt
├── Makefile
├── LICENSE
├── SECURITY.md
└── README.md
```

## Design principle

> **The file does not get to choose the machine's resource ceiling.**

AttendantForge aims to make that ceiling visible before another parser, extractor, or renderer is allowed to consume the file.

## License

MIT
