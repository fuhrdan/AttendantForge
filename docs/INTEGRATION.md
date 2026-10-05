# Integration guide

AttendantForge is intended to run **before** an untrusted ZIP is extracted or an
untrusted PDF is rendered/decoded by a richer application.

```text
Upload/download
      |
      v
Temporary non-executable storage
      |
      v
AttendantForge static scan
      |
 +----+----+
 |    |    |
ALLOW WARN BLOCK
 |    |    |
 v    v    v
next review quarantine
stage queue / reject
```

## Recommended handoff

Use `--json` and the stable process exit codes. Invoke the executable directly,
not through a shell, and apply a caller-side timeout. Treat scanner failures as a
fail-closed condition for public upload services.

```bash
attendantforge scan --json --profile upload-server file.pdf
```

Exit codes remain:

- `0`: ALLOW
- `10`: WARN / review
- `20`: BLOCK / quarantine
- `2`: invalid CLI or policy
- `3`: scan failure

The included `examples/upload-gateway/upload_gate.py` demonstrates this pattern
using only Python's standard library.
