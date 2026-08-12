# Roadmap

## 0.1 — Publishable reference implementation

- [x] Model-independent agent protocols
- [x] Canonical claim and spec digests
- [x] Complete HMAC-signed verification receipts
- [x] Fail-closed TrustGate
- [x] Per-case process execution and timeout
- [x] Cross-platform CI, tests, package build, and GitHub release automation

## 0.2 — Verification extensibility

- [ ] Verifier plugin registry
- [ ] Pytest, compiler, type-checker, linter, and schema-verifier adapters
- [ ] Structured evidence serialization and receipt export
- [ ] Append-only audit event interface

## 0.3 — Authorized specifications

- [ ] Separate `SpecProposal` from `AuthorizedSpec`
- [ ] Signed acceptance-criteria authority
- [ ] Criteria-to-obligation-to-evidence traceability
- [ ] Policy that critics may add but never remove baseline obligations

## 0.4 — Secure execution

- [ ] Pluggable container and microVM backends
- [ ] Resource and output quotas
- [ ] Default-deny network and credential isolation
- [ ] Cross-platform process-tree termination

## 0.5 — Multi-agent workflows

- [ ] Parallel workers and critics
- [ ] Model/provider provenance on every claim
- [ ] Receipt-gated DAG execution
- [ ] Selection among independently verified candidates

## 1.0 — Stable protocol

- [ ] Versioned receipt schema and compatibility policy
- [ ] External security review
- [ ] Reproducible benchmarks for false approval and false rejection
- [ ] Production deployment reference architecture
