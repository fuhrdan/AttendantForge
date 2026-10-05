# Contributing

Contributions are welcome.

## Rules for test samples

All adversarial fixtures must be intentionally bounded. Do not commit files designed to exhaust arbitrary systems, consume unbounded resources, or serve as deployable denial-of-service payloads.

Prefer synthetic metadata fixtures and small files that reproduce parser edge cases while remaining safe under ordinary CI limits.

## Style

- C11
- braces on the following line
- avoid global mutable state
- keep parser/resource accounting explicit
- check integer arithmetic before allocations
- prefer deterministic tests
