# Format Cost Models — v0.8

AttendantForge uses bounded, metadata-first inspection. It intentionally avoids
performing the expensive operation it is trying to predict.

## ZIP

Reads central-directory metadata and estimates declared expansion, entry count,
path safety, nested archive candidates, and recommended resource budgets. It does
not arbitrarily inflate compressed members during static analysis.

## PDF

Scans a bounded prefix for objects, streams, filters, image declarations,
references, xref structures, object streams, and incremental-update indicators.
It does not render pages or decode arbitrary PDF streams.

## GZIP

Reads the GZIP header and 32-bit `ISIZE` trailer. The trailer represents the
uncompressed size modulo 2^32, so AttendantForge reports the ratio as an estimate
and flags cases where wraparound could hide a larger true expansion.

```text
compressed file
     |
     +--> header / method / flags
     |
     +--> trailer ISIZE
             |
             v
      declared expansion ratio
```

## TAR

TAR is normally uncompressed, but it can still impose processing cost through
huge entry counts, large declared members, malformed headers, links, and unsafe
paths. AttendantForge walks 512-byte headers and skips payloads without copying
member data.

## PNG

PNG dimensions are read from `IHDR`. Estimated decoded memory is based on width,
height, color type, and bit depth. No IDAT decompression occurs.

## JPEG

AttendantForge walks bounded JPEG marker segments until it finds a Start Of Frame
marker and then calculates dimensions and approximate decoded pixel memory. It
does not decode entropy-coded image data.

## Common amplification model

Across formats, AttendantForge treats the stored file size as only one part of
the cost model:

```text
small input
   |
   +--> expansion / entry traversal / parser graph / decoded pixels
   |
   v
large CPU, RAM, disk, or traversal request
```

The product's goal is to identify that mismatch before the full parser, renderer,
or extractor receives the file.
