# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- Pluggable container and microVM execution backends.
- Signed acceptance-criteria authority.
- Parallel worker and critic orchestration.

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
