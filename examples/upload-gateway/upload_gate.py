#!/usr/bin/env python3
"""Minimal AttendantForge upload-gateway integration example.

This example does not accept network uploads itself. It shows the safe handoff
pattern a web application can use after it has written an upload to a temporary
file: invoke AttendantForge without a shell, parse JSON, and honor its exit code.
"""

import json
import subprocess
import sys
from pathlib import Path

ALLOW = 0
WARN = 10
BLOCK = 20


def inspect_upload(scanner: str, policy: str, upload: str) -> tuple[int, dict]:
    command = [scanner, "scan", "--json", "--policy", policy, upload]
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    if completed.returncode not in (ALLOW, WARN, BLOCK):
        raise RuntimeError(
            f"AttendantForge failed with exit {completed.returncode}: "
            f"{completed.stderr.strip()}"
        )

    return completed.returncode, json.loads(completed.stdout)


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: upload_gate.py <attendantforge> <policy.conf> <uploaded-file>")
        return 2

    scanner, policy, upload = sys.argv[1:]
    if not Path(upload).is_file():
        print("uploaded file does not exist", file=sys.stderr)
        return 2

    try:
        code, report = inspect_upload(scanner, policy, upload)
    except (RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print(f"scan failed closed: {exc}", file=sys.stderr)
        return 3

    decision = report["policy"]["decision"]
    print(f"AttendantForge decision: {decision}; risk={report['risk']['score']}/100")

    # Production gateways can quarantine WARN and BLOCK separately. This sample
    # fails closed for BLOCK and scanner errors while making WARN visible.
    if code == BLOCK:
        print("upload should be quarantined/rejected")
        return BLOCK
    if code == WARN:
        print("upload should be held for review")
        return WARN

    print("upload may continue to the next validation stage")
    return ALLOW


if __name__ == "__main__":
    raise SystemExit(main())
