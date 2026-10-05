# Threat Model

## Goal

AttendantForge estimates whether an untrusted file is likely to require a disproportionate amount of CPU, memory, disk, traversal, decompression, or rendering work relative to its stored size.

It is **not** an antivirus engine and does not attempt to prove that a file is malware.

## ZIP resource-exhaustion threat

A ZIP archive stores compressed members plus metadata describing those members. A resource-exhaustion archive abuses the difference between the archive's small stored representation and the work required to expand or traverse it.

Conceptually:

```text
small archive
     |
     v
+------------+
| ZIP parser |
+------------+
     |
     +--> member A --> large decoded output
     +--> member B --> large decoded output
     +--> nested archive --> more members
     |
     v
CPU + RAM + disk pressure
```

For an archive with members `1..n`, the aggregate decoded size is:

```text
U_total = sum(U_i)
```

and a simple expansion ratio is:

```text
R = U_total / C_total
```

where `C_total` is the stored compressed size and `U_total` is the declared or measured uncompressed size.

A defender should therefore consider more than the input file size. Relevant signals include:

- total entry count;
- declared total uncompressed bytes;
- per-entry and aggregate compression ratios;
- nested archive depth;
- duplicate or pathological paths;
- temporary disk requirements;
- cumulative extraction budget.

The defensive rule is simple: **the archive does not get to choose the machine's resource ceiling.**

## PDF resource-exhaustion threat

PDF is an object-based document format. A document can contain page trees, indirect objects, dictionaries, arrays, fonts, images, content streams, compressed streams, embedded content, and references among those objects.

Conceptually:

```text
PDF header
   |
   v
Catalog --> Pages --> Page --> Resources
                         |        |
                         |        +--> fonts/images
                         +--> content streams
                                  |
                                  v
                              decoders
                                  |
                                  v
                         rendering / allocation
```

A PDF can be small on disk while asking a parser or renderer to perform much more work. Resource pressure may arise from:

- highly compressed streams;
- large numbers of objects or streams;
- deeply nested structures;
- very large declared image dimensions;
- expensive rendering or repeated resource use;
- embedded content;
- aggregate work that is individually valid but excessive in total.

The vulnerable implementation pattern is not "PDF exists". It is:

```text
untrusted document
      |
      v
parser / decoder / renderer
      |
      v
unbounded work or allocation
      |
      v
resource exhaustion
```

AttendantForge's long-term model is to score **estimated resource pressure**, not to claim an exact amount of memory or CPU time for every reader.

## Out of scope

AttendantForge v0.5 does not:

- execute embedded scripts;
- render PDFs or decode PDF stream payloads;
- extract arbitrary ZIP contents during the static scan;
- create archive bombs or destructive PDF samples;
- determine whether a document contains malware;
- guarantee that a file is safe to open.

v0.5 retains bounded PDF static analysis and adds pipeline policy controls plus basic reference/xref consistency checks. Later releases can add xref-stream/object-stream awareness and an optional OS-constrained dynamic probe.


## Current defensive checks

AttendantForge v0.5 converts the threat model into static checks without expanding arbitrary payloads:

- declared compressed vs. uncompressed bytes and amplification ratio;
- entry-count and largest-entry pressure;
- ZIP64 metadata validation for single-disk archives;
- nested archive candidate counts;
- bounded confirmation of stored nested ZIP data;
- parent-directory traversal paths (`../` and `..\`);
- rooted/absolute extraction targets;
- recommended disk and memory budgets before extraction.

These checks do not prove a file is safe. They provide an inexpensive preflight risk estimate so a caller can allow, warn, quarantine, or pass the file to a separately resource-constrained sandbox.


## v0.5 PDF checks

The PDF analyzer adds a bounded preflight pass that does not render the document or inflate stream data. It inventories:

- indirect-object and stream counts;
- filter declarations and `/FlateDecode` use;
- maximum observed filter-chain length;
- numeric `/Length` declarations relative to stored file size;
- declared image dimensions and aggregate pixel workload;
- a simple RGBA memory-pressure estimate;
- embedded-file markers;
- dictionary/array nesting depth;
- xref, `startxref`, and EOF markers;
- indirect-reference counts and bounded unresolved-reference checks;
- `startxref` range validation and classic-xref target validation.

The resulting score estimates **resource pressure**, not malicious intent. A legitimate engineering drawing or image-heavy report can be expensive, while a maliciously constructed file may exploit implementation details not visible to static heuristics. The score is therefore intended to drive a policy decision, not replace a hardened parser or sandbox.


## v0.5 pipeline policy

A scanner finding is not automatically a malware verdict. v0.5 exposes explicit thresholds so an upload/download gateway can choose its own operational posture. Default decisions are ALLOW below 60, WARN from 60 through 79, and BLOCK at 80 or higher. `--strict` lowers the default blocking threshold to 60. Stable exit codes let a caller enforce that decision without scraping human-readable output.
