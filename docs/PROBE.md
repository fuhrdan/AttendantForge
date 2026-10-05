# Constrained Parser Probe

AttendantForge v0.7 adds an **opt-in isolated parser probe**. The probe does not
launch Acrobat, Preview, a ZIP extraction utility, or arbitrary third-party
handlers. It executes AttendantForge's own bounded parser in a child process and
measures what that parser actually consumed while the operating system enforces
resource ceilings.

## Why this exists

Static analysis answers:

> What resource cost does this file appear to request?

The probe adds a second question:

> How much CPU and memory did AttendantForge actually need to inspect it inside
> a constrained process?

This helps validate the static model while keeping the preflight operation
bounded.

## Usage

```bash
attendantforge probe suspicious.pdf
attendantforge probe --json suspicious.zip
attendantforge probe --memory-mib 128 --cpu-seconds 1 --timeout-ms 1500 upload.pdf
```

Default ceilings:

| Resource | Default |
|---|---:|
| Address-space/process memory | 256 MiB |
| CPU time | 2 seconds |
| Elapsed time | 3000 ms |
| Temporary files | none created by the v0.7 worker |

The command reports peak memory, CPU time, elapsed time, the static predicted
memory budget, and the ratio between measured peak memory and that prediction.

## Fail-safe decisions

A worker that reaches an enforced resource ceiling or elapsed timeout is treated
as a policy block and exits `20`. Infrastructure/worker failures exit `3`.
Normal risk-policy exit codes remain unchanged when the worker completes.

## Platform enforcement

- **Linux/Unix-like systems:** child process with address-space and CPU rlimits,
  parent-enforced wall-clock timeout, and child resource-usage accounting.
- **Windows:** Job Object process-memory and CPU-time limits plus a parent
  wall-clock timeout. Peak job memory and process CPU time are reported.

## Safety boundary

The v0.7 probe intentionally does **not**:

- decompress arbitrary nested ZIP members;
- render PDF pages;
- execute PDF actions/scripts;
- open embedded files;
- invoke the operating system's registered file handler;
- run an arbitrary user-supplied command.

Those operations would expand the attack surface of the scanner itself. Future
external-handler adapters should use a stronger disposable sandbox boundary.

If the constrained worker completes but produces a different static risk score
than the parent scan, AttendantForge treats that as degraded analysis under the
configured ceiling and fails closed as `LIMIT_HIT`. This catches cases where an
allocation failure is handled gracefully by a parser rather than terminated by
the operating system.
