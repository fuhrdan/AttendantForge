# Security Policy

AttendantForge is a defensive resource-cost analysis project.

Please do not submit weaponized archive bombs, intentionally destructive PDFs, or other samples designed to exhaust arbitrary systems as public issues or pull requests.

For testing, use bounded fixtures whose expanded size, recursion depth, object count, and execution time remain intentionally limited.

Security reports should describe the parser behavior, affected version, input characteristics, and mitigation without attaching a destructive proof-of-concept.

## Dynamic probe safety (v0.7)

`attendantforge probe` runs only AttendantForge's own bounded parser in a child
process under operating-system resource ceilings. It does not invoke registered
file handlers, arbitrary external commands, PDF JavaScript/actions, embedded
files, or general archive extraction. A probe timeout or enforced resource-limit
termination is treated as a block condition.
