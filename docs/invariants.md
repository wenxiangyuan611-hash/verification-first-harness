# Invariant Coverage

This matrix maps the project's seven principles to concrete 0.3.0-alpha controls. It is a
claim about the stated protocol boundary, not about arbitrary code running with the
same operating-system authority as the controller.

| Principle | 0.3.0-alpha control | Representative tests |
| --- | --- | --- |
| Every agent is untrusted | Every provider result must become a detached `AgentOutput` and then a quarantined `ClaimEnvelope`; providers never issue evidence or receipts. | provider shape tests, `test_all_agent_roles_use_the_same_claim_envelope` |
| Every output is a claim, not a fact | `SpecProposal` has no authority; SQLite persists agent payloads with `QUARANTINED`, never `VERIFIED`. | runtime persistence and protocol detachment tests |
| No unverified claim propagates | Failed runtime attempts omit raw payloads; only `ArtifactTrustGate` issues a payload-carrying `VerifiedArtifact`. | runtime repair integration, forbidden artifact construction tests |
| Challenge previous work | The Python `Critic` proposes bounded falsification obligations; generic repair claims point to their rejected parent. Generic challenge scheduling remains beta work. | critic policy tests, runtime repair lineage test |
| Prefer independent verification | Verifier plugins run behind a separate action boundary, evidence authority, and deterministic policy. | command verifier, denied verifier, forgery, and trace tests |
| Failure → repair → re-verification | Only signed `REJECTED` decisions enter the bounded loop; each attempt receives a new claim, evidence bundle, and receipt. | real subprocess failure/repair/re-verification test |
| Optimize error containment | Action-policy failures, plugin failures, malformed output, replay, and storage tampering fail closed without promoting a claim. | action gate, registry containment, durable replay, and SQLite tamper tests |

## Important qualification

The generic protocol can envelope every listed role, but the 0.3.0-alpha runtime
schedules one provider sequentially and its generic path does not yet invoke a
Critic. The original Python adapter still demonstrates explicit challenge. Generic
challenge scheduling is planned for 0.3.0-beta and parallel receipt-gated DAG
execution for 0.4.0.
