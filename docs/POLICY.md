# Policy configuration

AttendantForge v0.6 separates **file analysis** from **deployment policy**.
The analyzer produces a 0–100 resource-risk score; the policy decides when that
score becomes WARN or BLOCK.

## Precedence

1. built-in defaults
2. `--profile NAME`
3. `--policy FILE`
4. explicit `--warn-score`, `--block-score`, and `--strict`

This makes policy files reusable while preserving a deterministic command-line
override for CI/CD and incident-response use.

## Built-in profiles

| Profile | Warn | Block | Strict | Intended use |
|---|---:|---:|---|---|
| `desktop` | 60 | 80 | no | local interactive inspection |
| `upload-server` | 45 | 70 | no | internet-facing upload workflows |
| `high-security` | 30 | 60 | yes | highly untrusted/public submissions |

The profiles are conservative examples, not universal security guarantees.
Organizations should tune thresholds against their own corpus and false-positive
tolerance.

## File format

Policy files use a deliberately small `key=value` syntax:

```ini
profile=upload-server
warn_score=45
block_score=70
strict=false
```

Supported keys are `profile`, `warn_score`, `block_score`, and `strict`. Unknown
keys are rejected rather than silently ignored. Scores must be 0–100 and
`warn_score` must not exceed `block_score`.

`strict=true` ensures the effective block threshold is no higher than 60 unless
an explicit command-line `--block-score` override is supplied.
