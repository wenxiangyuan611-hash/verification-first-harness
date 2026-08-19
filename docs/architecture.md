# Architecture

## Objective

Verification-First Harness separates generation, verification, decision, and
propagation. Agents may propose specifications, claims, and challenges, but no
agent can certify its own output or issue downstream authority.

The architecture now has five deliberately decoupled layers:

1. a generic trust kernel for JSON-compatible claims and evidence;
2. a provider-neutral sequential agent runtime;
3. an action-policy plane that mediates consequential execution;
4. durable local quarantine and replay storage;
5. domain and provider adapters, including the Python coding loop retained from 0.1.x.

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

## Verification runtime

`VerificationRuntime` is the first executable composition of the generic kernel. It
opens and persists a run, authorizes the exact specification, invokes one Worker
`AgentProvider`, and converts the detached `AgentOutput` into a quarantined
`ClaimEnvelope`. It may then invoke a distinct Critic. The critic claim is also
quarantined, and deterministic policy may use it only to select checks from a
controller-owned optional catalog. Baseline obligations cannot be removed or
replaced. The runtime then collects verifier observations, authenticates evidence,
asks the kernel for a deterministic decision, and persists the receipt and any
verified artifact.

Only `REJECTED` decisions enter the bounded repair loop. `INCONCLUSIVE` and `ERROR`
stop instead of being silently reinterpreted as a repairable correctness failure.
Repair requests may receive the failed claim and observations inside the untrusted
work zone. Failed `RuntimeAttempt` results expose claim identity and decision
metadata, but not the raw failed payload. Only a successful `VerifiedArtifact`
crosses into the trusted downstream zone.

`CallableAgentProvider` adapts SDK clients without granting them verification
authority. `CommandAgentProvider` is a local strict-JSON wire adapter: it sends a
canonical request on stdin, expects exactly `payload_type` and `payload` on stdout,
and never interpolates model output into a shell command.

`CodexAgentProvider` is the first first-party SDK adapter. It maps each request to a
fresh ephemeral Codex thread, requests the exact `AgentOutput` JSON Schema, and
strictly re-parses the final response before returning it to the runtime. It defaults
to read-only filesystem access, selects deny-all approval, disables optional external
tools where the SDK exposes reliable overrides, and omits full-access mode. Even so,
the provider remains outside the trusted computing base and cannot issue evidence or
receipts.

`OpenCodeAgentProvider` is the first first-party CLI adapter for a second agent
runtime. It invokes documented non-interactive JSON mode without a shell, injects a
named deny-all or read-only agent configuration, requires an explicit working
directory, parses each JSON event locally, and strictly re-parses the assembled final
`AgentOutput`. OpenCode permission controls reduce accidental authority but do not
turn the external CLI, inherited configuration, plugins, or host process into a
security sandbox.

`ChallengeScheduler` gives a Critic bounded influence without treating criticism as
truth. The Critic receives a quarantined Worker claim and may return only IDs from a
pre-authorized `VerificationObligation` catalog. `RuntimeChallengePolicy` rejects
self-review by provider identity, unknown IDs, duplicate IDs, oversized rationale,
and any attempt to overlap or replace baseline checks. Critic rationale never enters
the verification plan or repair feedback; only independent observations do.

## Action policy plane

Action authorization and claim verification answer different questions:

- `ActionGate`: may this exact agent or verifier operation execute?
- `ArtifactTrustGate`: may this exact claim payload propagate downstream?

`ActionGate` evaluates `ActionRequest` values before calling the operation. The
reference allow-list policy denies unknown kinds, and `REQUIRE_APPROVAL` fails closed
when no resolver returns an actual boolean approval. Policy errors and malformed
decisions never execute the proposed operation.

This gate does not prove that an allowed operation succeeded or that its output is
correct. Its output must still enter the claim and evidence pipeline.

## Verifier plugins

`VerifierRegistry` routes each obligation kind to exactly one `VerifierPlugin`.
Unsupported kinds, plugin exceptions, malformed observations, identity mismatches,
and denied verifier actions become explicit `ERROR` observations. A plugin never
computes the final verdict.

The beta `CommandVerifierPlugin` executes an authorized argv list without a shell
and sends the canonical claim envelope on stdin. It is suitable for local
deterministic tools, but it is not a container or hostile-code sandbox.

## Durable local trust labels

`SQLiteRunStore` persists the context and each protocol value under one explicit
label: `AUTHORIZED`, `QUARANTINED`, `AUTHENTICATED_EVIDENCE`, `DECISION_ONLY`, or
`VERIFIED`. Persistence never upgrades a label. Stored payload digests are checked
when records are read.

`SQLiteReceiptUseStore` uses an immediate transaction and a unique receipt ID to
preserve single-use propagation across process restarts. SQLite file integrity is
not cryptographic authentication; a production controller still needs protected,
transactional storage and external audit guarantees.

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
5. action policy, approval resolution, and complete mediation of controlled effects;
6. transactional receipt-use storage and the execution, retrieval, or measurement
   isolation platform;
7. the process runtime itself for in-process deployments.

Agents and model providers remain outside this trusted base. A verifier is not an
LLM role here; it is an evidence-producing security boundary whose implementation
and tools must be reviewed independently.

## Remaining architectural boundary

The kernel and runtime are domain-neutral, but orchestration is still sequential.
The beta provides Codex and OpenCode providers, one optional bounded Critic stage,
and a generic command verifier, but not yet repository claim adapters. Container
isolation, durable hash-chained audit, parallel branches, receipt-gated DAG
scheduling, and non-code verifier packs remain roadmap work.
