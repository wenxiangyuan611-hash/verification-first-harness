# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- An optional first-party `CodexAgentProvider` over the official `openai-codex`
  Python SDK, constrained to the tested `0.147.x` API line.
- A fixed Codex structured-output schema, fresh ephemeral threads, read-only default
  sandbox, deny-all approval and restrictive external-tool overrides, and explicit
  quarantined-directory requirement for workspace writes.
- Fail-closed tests for missing SDKs, malformed and forged model output, duplicate
  keys, oversized responses, SDK errors, and mutable schema attacks.
- A runnable read-only Codex example that enters the same quarantine, independent
  verifier, signed receipt, and artifact-gate path as other providers.

### Changed

- The development package version is now `0.3.0b1`.
- The package status classifier and documentation now identify the current line as
  beta while retaining the research-prototype warning.

### Planned

- Pluggable container and microVM execution backends.
- Parallel worker and critic orchestration.
- First-party Claude and OpenCode provider adapters.
- Durable append-only audit storage.

## [0.3.0-alpha.1] - 2026-08-19

### Added

- A provider-neutral `VerificationRuntime` with bounded rejection, repair, and
  re-verification control flow.
- Detached `AgentRequest` and `AgentOutput` values, a callable SDK adapter, and a
  strict-JSON local command provider that does not invoke a shell.
- A fail-closed `ActionGate` with allow, deny, and independent-approval verdicts.
- A verifier plugin registry and external command verifier over canonical claim
  envelopes.
- SQLite persistence for contexts, authorized specs, quarantined claims,
  authenticated evidence, decision receipts, verified artifacts, and single-use
  receipt consumption across local controller restarts.
- A runtime demo/inspection CLI and adversarial tests for action denial, malformed
  providers, verifier failures, storage tampering, and restart replay.

### Changed

- The development package version is now `0.3.0a1`.
- The 0.3 roadmap now targets a general agent verification runtime; repository code
  review is one domain pack rather than the project identity.

## [0.2.0] - 2026-08-13

### Added

- A domain-neutral, versioned trust protocol with fresh `RunContext` values and
  role-neutral, detached `ClaimEnvelope` values.
- Independent `SpecProposal` authorization and exact-contract `AuthorizedSpec`
  signatures.
- Authenticated `EvidenceBundle` values separated from controller-signed
  `DecisionReceipt` values.
- Explicit `VERIFIED`, `REJECTED`, `INCONCLUSIVE`, and `ERROR` verdicts with
  deterministic precedence and acceptance-criteria traceability.
- Single-use receipt consumption, cross-run replay checks, capability-oriented
  `VerifiedArtifact` propagation, and a hash-chained audit sink interface.
- A compatibility adapter that routes the sequential Python engine through the
  generic kernel while preserving 0.1.x diagnostic fields.
- Adversarial tests for unauthorized contract replacement, forged evidence and
  receipts, incomplete traces, cross-claim/cross-run reuse, repair lineage, and
  forbidden artifact construction.

### Changed

- All authenticated decisions, including rejected decisions, are validated and
  signed before repair or termination control flow proceeds.
- Successful Python engine results expose `context`, `verdict`, `decision_receipt`,
  and `artifact`; non-successful results never expose a verified artifact.
- The in-memory replay registry and audit chain serialize mutations for future
  parallel callers.

### Security

- Acceptance criteria are no longer implicitly trusted merely because a Planner
  returned them; the compatibility adapter checks exact registry authorization.
- Evidence and decision authorities use separate keys, limiting the authority of
  the verification boundary.

## [0.1.1] - 2026-08-12

### Added

- A fail-closed component-call boundary for exceptions and malformed return values.
- A configurable challenge policy that limits critic obligation kinds, IDs, counts,
  descriptions, and payload sizes.
- Structured component failure records in rejected engine results.
- Canonical detached snapshots for specs, claims, critic payloads, and repair receipts
  exposed across untrusted component boundaries.
- Adversarial tests for controller termination attempts, forged receipts, invalid
  signature decisions, malformed critic output, and failed repairs.

### Changed

- Failed receipts are now checked for completeness, final evidence, exact bindings,
  and signature authenticity before they may inform a repair.
- Planner and worker identity fields are checked against the requested task and
  expected attempt.
- Component failures now produce a controlled `REJECTED` result instead of escaping
  the engine.

## [0.1.0] - 2026-08-12

### Added

- Verification-first propose, challenge, verify, repair, and re-verify loop.
- Canonical claim and specification digests.
- HMAC-signed receipts bound to obligations and evidence.
- Per-test fresh-process execution with parent-enforced timeouts.
- Generic task entrypoints and deterministic demo agents.
- Public package metadata, CI, release automation, tests, and project governance.
