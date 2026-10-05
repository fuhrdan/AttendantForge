# Batch and Quarantine Scanning (v0.9)

AttendantForge can scan a quarantine or upload directory without opening files in their native applications.

```bash
attendantforge batch --recursive --profile upload-server --ndjson results.ndjson ./quarantine
attendantforge batch --csv results.csv ./incoming
```

Exit codes summarize the strongest result: `0` allow, `10` at least one warning, `20` at least one block, and `3` for scan errors when no stronger policy decision exists.

## Extension/signature mismatch

The scanner compares recognized filename extensions with file magic. A file named `invoice.pdf` whose bytes identify as ZIP is flagged. This is intentionally described as an extension/signature check, not full MIME detection, so v0.9 remains dependency-free.

## Format admission

Policy files may include:

```ini
allow_formats=ZIP,PDF,PNG,JPEG
deny_formats=GZIP,TAR
```

`allow_formats=*` permits every recognized/unknown format unless separately denied.
