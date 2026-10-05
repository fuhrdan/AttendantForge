#!/usr/bin/env python3
"""Dependency-free release hygiene checks for AttendantForge source packages."""
from pathlib import Path
import re, sys

root = Path(__file__).resolve().parents[1]
errors = []
required = [
    'README.md','LICENSE','SECURITY.md','CONTRIBUTING.md','CHANGELOG.md',
    'docs/API_CONTRACT.md','docs/AUDIT_TELEMETRY.md','docs/RELEASE.md',
    'include/attendantforge.h','src/main.c','tests/test_main.c'
]
for rel in required:
    if not (root / rel).exists():
        errors.append(f'missing required file: {rel}')

header = (root/'include/attendantforge.h').read_text(encoding='utf-8')
cmake = (root/'CMakeLists.txt').read_text(encoding='utf-8')
readme = (root/'README.md').read_text(encoding='utf-8')
for needle in ['#define AF_VERSION "1.0.0"', '#define AF_TELEMETRY_SCHEMA "1.0"', '#define AF_CLI_CONTRACT "1.0"']:
    if needle not in header:
        errors.append(f'header contract missing: {needle}')
if 'project(AttendantForge VERSION 1.0.0' not in cmake:
    errors.append('CMake project version is not 1.0.0')
if '# AttendantForge v1.0.0' not in readme:
    errors.append('README release heading is not v1.0.0')

for banned in ['build/', 'build-make/']:
    if (root/banned.rstrip('/')).exists():
        errors.append(f'build artifact directory present: {banned}')

if errors:
    print('AttendantForge release check FAILED')
    for e in errors: print(f' - {e}')
    sys.exit(1)
print('AttendantForge v1.0.0 release check PASS')
