# Security Policy

## Supported versions

Only the latest released minor version receives security fixes while the project
is in alpha.

## Reporting a vulnerability

Please use GitHub's **Report a vulnerability** private security-advisory feature.
Do not open a public issue for vulnerabilities involving code execution,
credential exposure, receipt forgery, sandbox escape, or trust-gate bypass.

Include a minimal reproduction, affected version, expected impact, and any
suggested mitigation. Maintainers should acknowledge a complete report within
seven days and coordinate disclosure after a fix is available.

## Important execution boundary

The built-in subprocess executor is a reliability boundary, not a security
sandbox. It contains ordinary crashes and enforces a timeout, but hostile Python
can still access resources available to the operating-system account. Execute
untrusted candidates in a separately managed container, microVM, VM, or OS-level
sandbox with no ambient credentials and restricted network, filesystem, CPU,
memory, disk, output, and process access.

The generic trust kernel's Python object boundaries are also not a sandbox against
hostile modules in the same interpreter. Production deployments should isolate
agent adapters and verification tools, keep specification, evidence, and receipt
keys in separate protected controller boundaries, and replace the in-memory replay
and audit stores with atomic durable services.
