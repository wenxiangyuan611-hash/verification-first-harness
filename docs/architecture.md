# Architecture

## Objective

Verification-First Harness separates generation from authorization. Agents may
propose plans, implementations, and challenges, but none may grant propagation
authority to its own output.

## Components

- **Planner** proposes or retrieves a task contract.
- **Worker** emits an untrusted `Claim` and may repair it from failed evidence.
- **Critic** attempts falsification by proposing additional `Obligation` values.
- **AgentCallBoundary** converts component exceptions and malformed values into
  structured, fail-closed rejections.
- **ChallengePolicy** authorizes bounded critic proposals while preserving baseline
  obligations.
- **Verifier** independently executes supported obligations and emits `Evidence`.
- **VerificationReceipt** cryptographically binds the complete verification run.
- **TrustGate** validates the receipt and is the only path to approved propagation.

Agents are replaceable through Python structural protocols. Agent count and model
provider do not change the trust model.

## Current implementation boundary

Version 0.1.1 is a deliberately narrow reference implementation. It treats Worker
code as the primary untrusted `Claim`; Critic output is limited to proposed
verification obligations, and registered task contracts are assumed to have
been authorized out of band. General claim envelopes for Planner and Critic
outputs, multiple concurrent agents, and receipt-gated DAG execution remain
roadmap work. The distinction between the target trust model and the guarantees
implemented by this release is intentional and security-relevant.

## Trusted computing base

No system can derive a trustworthy decision if every component and every input is
untrusted. The minimal trusted computing base is:

1. the authorized acceptance criteria or policy source;
2. the verifier control-plane implementation;
3. the receipt-signing key and secret-management boundary;
4. the TrustGate implementation;
5. the isolation platform used for hostile candidate execution.

The reference `PlannerAgent` uses an in-memory task registry and assumes its
registered contracts were authorized out of band. Production deployments must
not treat arbitrary planner output as an authorized task contract.

## Protocol binding

A receipt signature protects:

- run ID;
- claim digest;
- specification digest;
- attempt number;
- protocol version;
- ordered obligation set;
- ordered evidence set.

TrustGate recalculates digests, checks attempt and protocol equality, compares the
exact obligation set, verifies evidence completeness, and authenticates the HMAC
before invoking a downstream callback.

Failed receipts cross a narrower quarantine boundary into the repair loop. They
must be complete, final, exactly bound, and authentically signed before a Worker
may consume their evidence. They never receive downstream propagation authority.

## Failure semantics

Unsupported obligations, invalid inputs, malformed child responses, exceptions,
timeouts, test mismatches, missing evidence, and signature failures all fail
closed. A failed receipt can be supplied to a Worker for repair but cannot pass
through TrustGate.

Component exceptions, `SystemExit`, unexpected return types, invalid attempt or
task identities, and critic policy violations are normalized into a structured
failure and reject the current run. User cancellation via `KeyboardInterrupt`
remains under caller control.

The controller canonicalizes and detaches specs, claims, critic payloads, and
repair receipts when they cross untrusted component boundaries. Frozen dataclass
shells alone do not make nested JSON values immutable; detached snapshots prevent
in-place mutation from altering controller-owned protocol state.
