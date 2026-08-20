# Invariant Coverage

This matrix maps the project's seven principles to concrete 0.3.0-beta controls. It is a
claim about the stated protocol boundary, not about arbitrary code running with the
same operating-system authority as the controller.

| Principle | 0.3.0-beta control | Representative tests |
| --- | --- | --- |
| Every agent is untrusted | Every provider result, including Codex and OpenCode output, must become a detached `AgentOutput` and then a quarantined `ClaimEnvelope`; providers never issue evidence or receipts. | provider shape tests, `test_all_agent_roles_use_the_same_claim_envelope` |
| Every output is a claim, not a fact | `SpecProposal` has no authority; SQLite persists agent payloads with `QUARANTINED`, never `VERIFIED`. | runtime persistence and protocol detachment tests |
| No unverified claim propagates | Failed runtime attempts omit raw payloads; only `ArtifactTrustGate` issues a payload-carrying `VerifiedArtifact`. | runtime repair integration, forbidden artifact construction tests |
| Challenge previous work | The generic runtime may invoke a distinct Critic before verification. The Critic can select only controller-owned optional checks; its rationale remains quarantined and cannot decide the verdict. | challenge policy/scheduler tests, challenged repair integration test |
| Prefer independent verification | Verifier plugins run behind a separate action boundary, evidence authority, and deterministic policy. | command verifier, denied verifier, forgery, and trace tests |
| Failure → repair → re-verification | Only signed `REJECTED` decisions enter the bounded loop; each attempt receives a new claim, evidence bundle, and receipt. | real subprocess failure/repair/re-verification test |
| Optimize error containment | Action-policy failures, plugin failures, malformed output, replay, and storage tampering fail closed without promoting a claim. | action gate, registry containment, durable replay, and SQLite tamper tests |

## Important qualification

The generic protocol can envelope every listed role. The 0.3.0-beta runtime schedules
one Worker and an optional distinct Critic sequentially; it does not yet run parallel
branches or a receipt-gated DAG. Critic output is not verified truth. Deterministic
policy may use only its bounded check selection, and final authority remains with
independently authenticated evidence and the artifact gate. Parallel receipt-gated
DAG execution remains planned for 0.4.0.
