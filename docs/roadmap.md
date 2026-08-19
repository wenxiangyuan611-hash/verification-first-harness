# Roadmap

Verification-First Harness is a verification and propagation control plane for
untrusted agent outputs. It is not an agent-voting framework. Coding is the first
reference domain because it has strong independent verification tools.

The primary reliability objective is false propagation rate: an unverified or
incorrect claim must not acquire trusted downstream authority inside the stated
threat model.

## 0.1.0 — Publishable reference implementation

- [x] Model-independent agent protocols
- [x] Canonical claim and spec digests
- [x] Complete HMAC-signed verification receipts
- [x] Fail-closed TrustGate
- [x] Per-case process execution and timeout
- [x] Cross-platform CI, tests, package build, and GitHub release automation

## 0.1.1 — Containment hardening

- [x] Fail-closed boundary for component exceptions and malformed values
- [x] Structured component failure records
- [x] Challenge policy with kind, ID, count, description, and payload limits
- [x] Immutable harness baseline obligations
- [x] Authentication of failed receipts before repair
- [x] Detached canonical snapshots across untrusted component boundaries
- [x] Adversarial containment tests

## 0.2.0 — Generic verification kernel

- [x] Separate `SpecProposal` from `AuthorizedSpec`
- [x] General `ClaimEnvelope` for every agent role
- [x] Explicit `VERIFIED`, `REJECTED`, `INCONCLUSIVE`, and `ERROR` verdicts
- [x] Run context and receipt replay protection
- [x] Capability-oriented `VerifiedArtifact` downstream boundary
- [x] Stable JSON receipt export and append-only audit event interface
- [x] Criteria-to-obligation-to-evidence traceability
- [x] Separate evidence and decision-receipt authorities
- [x] Compatibility bridge for the sequential Python repair engine

## 0.3.0-alpha.1 — Provider-neutral verification runtime

- [x] Provider-neutral agent request and output protocol
- [x] Callable SDK adapter and strict-JSON local command adapter
- [x] Pre-execution `ActionGate` with deny, allow, and approval-required verdicts
- [x] Verifier plugin registry with contained error observations
- [x] Generic external-command verifier with no shell interpolation
- [x] Bounded rejection, repair, and re-verification runtime
- [x] SQLite run, claim, evidence, receipt, artifact, and replay persistence
- [x] Explicit durable trust labels that never promote quarantined claims
- [x] CLI runtime demo and durable-record inspection
- [x] End-to-end subprocess and restart replay tests

## 0.3.0-beta — Real agent and coding-domain pilot

- [ ] First-party Codex and Claude provider examples with pinned wire contracts
- [ ] Repository, source-tree, Git patch, and build-artifact claim types
- [ ] Pytest, compiler, type-checker, linter, schema, and browser verifier packs
- [ ] Generic critic/challenge scheduling before verification
- [ ] Container execution backend with default-deny network and resource quotas
- [ ] Durable hash-chained audit sink and action-decision records
- [ ] CLI commands for configured run, verify, resume, inspect, and replay
- [ ] Public fixtures and false-propagation test corpus

## 0.4.0 — Controlled parallel multi-agent workflows

- [ ] Parallel workers, critics, and independent verifiers
- [ ] Per-branch timeout, budget, cancellation, and isolation
- [ ] Model/provider provenance on every claim
- [ ] Receipt-gated DAG execution
- [ ] Trusted edges accept only `VerifiedArtifact`; challenge edges remain quarantined
- [ ] Selection only among independently verified candidates
- [ ] Correlated-failure measurements without majority-vote authorization

## 0.5.0 — Experimental non-code domain packs

- [ ] Math verification through calculators and symbolic solvers
- [ ] Source and citation verification for research claims
- [ ] Learning-answer traceability and rubric adapters
- [ ] Fact-claim freshness and authority checks
- [ ] Mandatory `INCONCLUSIVE` outcome when no independent oracle exists

## 1.0.0 — Stable protocol

- [ ] Versioned claim, evidence, receipt, and verdict schemas
- [ ] Compatibility and migration policy
- [ ] External security review
- [ ] Property-based, fuzz, mutation, and adversarial testing
- [ ] Reproducible false-approval and false-rejection benchmarks
- [ ] Production deployment reference architecture
- [ ] Signed release, SBOM, and build provenance

## Deliberate non-goals before 1.0

- Agent majority voting as a substitute for independent evidence
- A general hallucination score with no trusted truth source
- A broad chat UI before the verification protocol is stable
- Provider count as a reliability metric
- Distributed orchestration before local containment invariants are testable
