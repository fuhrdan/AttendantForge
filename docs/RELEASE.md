# Release and Installation Guide

## Supported build environments

AttendantForge is portable C11. CI validates current GitHub-hosted Ubuntu,
Windows, and macOS runners with CMake. The Makefile is intended for POSIX-like
build environments.

## Build from source

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Install with CMake

```bash
cmake --install build --prefix ./stage
```

On Unix-like systems, use an appropriate system prefix if desired. The install
step includes the executable, example policies, core documentation, README,
license, and security policy.

## Makefile build

```bash
make
make test
```

The binary is written to `build-make/attendantforge`.

## Release hygiene

Before tagging a release:

```bash
python3 scripts/release-check.py
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Then create a source-only archive excluding `.git`, `build`, and `build-make`.

## Recommended Git tag

`v1.0.0`
