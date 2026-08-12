# Architecture

## Objective

Verification-First Harness separates generation, verification, decision, and
propagation. Agents may propose specifications, claims, and challenges, but no
agent can certify its own output or issue downstream authority.

The architecture has two layers:

1. a generic trust kernel for JSON-compatible claims and evidence;
2. a sequential Python coding adapter retained from 0.1.x.

## Generic trust kernel

### Protocol values

- `RunContext` gives each run a fresh ID, task identity, nonce, and protocol version.
- `SpecProposal` is an untrusted proposed contract.
- `AuthorizedSpec` combines the exact proposal with a `SpecAuthority` signature.
- `ClaimEnvelope` stores a detached payload, producer role, attempt, and parent IDs.
- `VerificationObligation` maps one check to authorized acceptance criteria.
- `Observation` records the result of exactly one obligation.
- `EvidenceBundle` authenticates the complete ordered obligations and observations.
- `DecisionReceipt` binds the deterministic verdict to the context, authorized spec,
  claim, evidence bundle, verifier identity, attempt, trace, and protocol version.
- `VerifiedArtifact` is a capability-like wrapper issued only after full validation.

The generic wire protocol is version 3.0; it is intentionally versioned separately
from the Python package release, which introduces it in package version 0.2.0.

### Trusted control flow

1. An agent emits `SpecProposal`; it has no authority by itself.
2. `SpecAuthority` authorizes the exact proposal or rejects it.
3. An agent output enters quarantine as `ClaimEnvelope`.
4. An independent backend performs obligations and `EvidenceAuthority` authenticates
   the resulting `EvidenceBundle`.
5. `DecisionPolicy` checks completeness, exact ordering, known criterion mappings,
   full criterion coverage, and status precedence.
6. `ReceiptAuthority` signs the resulting `DecisionReceipt`.
7. The kernel validates the signed decision even when it is not successful.
8. Only a `VERIFIED` receipt can be atomically consumed by `ArtifactTrustGate` to
   issue `VerifiedArtifact`.
9. Other verdicts remain quarantined and may drive repair or termination.

`KernelDecision` intentionally contains no raw claim field. A caller that uses the
generic API must obtain the payload from `artifact`, so a failed decision cannot
accidentally carry an approved-looking claim downstream.

## Decision semantics

The built-in deterministic policy uses explicit precedence:

1. any `ERROR` observation produces `ERROR`;
2. otherwise, any `INCONCLUSIVE` produces `INCONCLUSIVE`;
3. otherwise, any `FAILED` produces `REJECTED`;
4. only a complete all-`PASSED` set produces `VERIFIED`.

Every authorized acceptance criterion must be mapped to at least one obligation.
Every observation must exactly match its ordered obligation. Unknown or uncovered
criteria fail closed before a receipt is signed.

## Authorities and keys

The reference implementation provides separate HMAC-SHA-256 authorities:

- `HMACSpecAuthority` for exact acceptance-contract approval;
- `HMACEvidenceAuthority` for verifier evidence;
- `HMACReceiptAuthority` for controller decisions.

The evidence and receipt keys are deliberately separate. A verifier that can attest
observations should not automatically possess the key that signs controller
decisions. Production deployments may replace the protocols with asymmetric
signatures, remote policy services, hardware-backed keys, or other authorities.

## Replay and audit

Receipts are bound to a fresh run context and nonce. `InMemoryReceiptUseStore`
atomically permits one successful consumption per receipt ID and detects reuse with
changed contents. `InMemoryAuditSink` serializes append operations into a
hash-chained event sequence and can verify that chain.

Both are process-local reference implementations. Distributed controllers need a
transactional persistent receipt store and durable append-only audit system.

## Python compatibility adapter

`TrustGateEngine` continues the 0.1.x sequence:

`PLAN -> WORK -> CHALLENGE -> VERIFY -> REPAIR -> RE-VERIFY`

The planner task registry is snapshotted as an out-of-band authorization policy.
Planner output that differs from the registered contract is rejected before the
Worker runs. Legacy verifier receipts are authenticated by the old gate and then
bridged into an authenticated generic evidence bundle. Each attempt receives a
generic signed decision, and only the final verified attempt receives an artifact.

For compatibility, engine results retain legacy `claim`, `receipt`, `status`, and
`failure` fields. New fields are `context`, `verdict`, `decision_receipt`, and
`artifact`. Legacy fields are diagnostic values; only `artifact` grants generic
propagation authority.

## Trusted computing base

No useful system can make every component untrusted simultaneously. The minimal
trusted computing base includes:

1. the authorized acceptance-criteria source and its policy/key boundary;
2. the independent evidence collector and evidence-authentication boundary;
3. deterministic decision policy and receipt authority;
4. `ArtifactTrustGate` plus replay storage;
5. the execution, retrieval, or measurement isolation platform;
6. the process runtime itself for in-process deployments.

Agents and model providers remain outside this trusted base. A verifier is not an
LLM role here; it is an evidence-producing security boundary whose implementation
and tools must be reviewed independently.

## Remaining architectural boundary

The kernel is domain-neutral, but orchestration is still sequential and the only
built-in domain adapter verifies small Python function claims. Repository-level
plugins, container isolation, parallel branches, receipt-gated DAG scheduling, and
non-code verifier packs remain roadmap work.
