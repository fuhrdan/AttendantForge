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

AttendantForge v0.1 does not:

- execute embedded scripts;
- render PDFs;
- extract ZIP contents;
- create archive bombs or destructive PDF samples;
- determine whether a document contains malware;
- guarantee that a file is safe to open.

Later releases add format-aware static analysis while retaining strict resource budgets and bounded test fixtures.
