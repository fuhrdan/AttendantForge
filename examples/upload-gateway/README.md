# Upload gateway example

`upload_gate.py` demonstrates the intended v0.6 integration pattern after an
application has saved an untrusted upload to a temporary file.

```bash
python3 upload_gate.py ../../build/attendantforge \
  ../../config/attendantforge.conf.example upload.pdf
```

The example deliberately uses `subprocess.run([...])` rather than a shell command,
sets a timeout, parses `--json`, and honors AttendantForge's stable exit codes.
A production service should also place the temporary upload in non-executable,
quota-controlled storage and quarantine WARN/BLOCK results before any renderer or
extractor opens them.
