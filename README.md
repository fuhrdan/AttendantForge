# AttendantForge

**Pre-open resource-cost analysis for untrusted files.**

AttendantForge is a defensive C utility designed to answer a question traditional malware scanners do not always answer:

> **How much computational work might this file ask the machine to perform compared with how small the file looks?**

Version **0.2.0** adds a real ZIP central-directory analyzer. It reads archive metadata **without extracting members** and reports entry count, compressed and declared uncompressed totals, aggregate expansion ratio, worst per-entry ratio, and a bounded resource-risk score.

> AttendantForge is not an antivirus engine and does not claim a file is malware-free or safe to open.

## What v0.2 adds

- ZIP End of Central Directory discovery
- central-directory validation
- entry counting
- total compressed payload size
- total declared uncompressed size
- aggregate expansion ratio
- maximum per-entry expansion ratio
- largest declared expanded member
- ZIP-specific risk scoring
- malformed/unsupported metadata warnings
- bounded metadata-only test fixtures

No archive contents are extracted during the v0.2 scan.

## Why this exists

Two useful examples are ZIP expansion attacks and PDF resource-exhaustion documents.

A ZIP may be small on disk yet represent a much larger extracted data set. A PDF may be small on disk yet contain compressed streams, large object graphs, image dimensions, nested structures, or rendering instructions that request disproportionate CPU, memory, or disk resources.

AttendantForge treats these as **resource-accounting problems** rather than merely signature-detection problems.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for diagrams and defensive descriptions of both attack classes.

## v0.2 architecture

```text
untrusted file
      |
      v
signature probe
      |
      +-------------------+
      |                   |
      v                   v
     ZIP                  PDF
      |                   |
      v                   v
EOCD locator        signature only
      |
      v
central directory
      |
      +--> entry count
      +--> compressed bytes
      +--> declared expanded bytes
      +--> expansion ratios
      |
      v
resource-risk score
```

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
./build/attendantforge scan archive.zip
./build/attendantforge scan suspicious.pdf
./build/attendantforge --version
```

Example:

```text
AttendantForge v0.2.0

File:        archive.zip
Type:        ZIP
Size:        1.82 MiB

ZIP resource metadata
---------------------
Entries:                 8412
Compressed payload:      1.64 MiB
Declared expanded data:  2710.00 MiB
Aggregate ratio:         1652.44x
Maximum entry ratio:     2190.12x
Largest entry expanded:  63.00 MiB
Central directory:       VALID

Risk score:  82 / 100
Risk level:  CRITICAL
Notes:       ZIP central directory parsed without extracting file contents. Extreme aggregate expansion ratio. ...
```

## Important limitations

v0.2 deliberately stays metadata-first. It does **not**:

- extract ZIP members;
- recursively inspect nested archives;
- fully account for ZIP64 archives;
- validate CRCs or decompressed content;
- inspect file paths for traversal anomalies;
- perform deep PDF analysis.

Those are later roadmap items. A LOW score is therefore a resource-risk observation based on the features currently implemented, not a guarantee of safety.

## Risk levels

| Score | Level |
|---:|---|
| 0-29 | LOW |
| 30-59 | MEDIUM |
| 60-79 | HIGH |
| 80-100 | CRITICAL |

Current ZIP scoring considers aggregate expansion ratio, worst per-entry ratio, declared expanded size, and entry count.

## Safety model

The project uses bounded fixtures and static metadata analysis. It does not ship generators for destructive ZIP bombs or PDFs intended to consume unbounded resources.

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
│   ├── main.c
│   ├── zip_analyzer.c
│   └── zip_analyzer.h
├── tests/test_main.c
├── CMakeLists.txt
├── Makefile
├── LICENSE
├── SECURITY.md
└── README.md
```

## Design principle

> **The file does not get to choose the machine's resource ceiling.**

## License

MIT
