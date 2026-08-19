# Invariant Coverage

This matrix maps the project's seven principles to concrete 0.2.0 controls. It is a
claim about the stated protocol boundary, not about arbitrary code running with the
same operating-system authority as the controller.

| Principle | 0.2.0 control | Representative tests |
| --- | --- | --- |
| Every agent is untrusted | Every supported role uses `ClaimEnvelope`; agent APIs cross fail-closed component boundaries. | `test_all_agent_roles_use_the_same_claim_envelope`, containment tests |
| Every output is a claim, not a fact | `SpecProposal` has no authority; `ClaimEnvelope` is quarantined and detached. | `test_spec_proposal_requires_independent_authorization`, `test_claim_envelope_is_role_neutral_and_detaches_payload` |
| No unverified claim propagates | Generic failed decisions omit raw claims; only `ArtifactTrustGate` issues `VerifiedArtifact`. | `test_non_verified_verdicts_never_carry_claim_payload`, `test_artifact_cannot_be_constructed_outside_trust_gate` |
| Challenge previous work | Python `Critic` proposes bounded falsification obligations; repair claims point to their failed parent. | `test_default_worker_stub_is_challenged_and_rejected`, repair-lineage integration test |
| Prefer independent verification | Evidence has a separate authenticated authority; deterministic policy—not an agent—computes verdicts. | evidence forgery, trace coverage, and observation-order tests |
| Failure → repair → re-verification | Rejected authenticated evidence may enter the bounded repair loop; each attempt receives a new claim and receipt. | `test_failure_repair_and_reverification_is_normal_control_flow` |
| Optimize error containment | Strict shape checks, signature binding, replay protection, explicit non-success verdicts, and audit history fail closed. | replay, receipt tamper, component failure, and policy-boundary tests |

## Important qualification

The generic protocol can envelope every listed role, but 0.2.0 does not yet schedule
all of them through a parallel graph. The built-in executable workflow remains the
sequential Python Planner/Worker/Critic/Verifier adapter. Parallel receipt-gated DAG
execution is planned for 0.4.0.
