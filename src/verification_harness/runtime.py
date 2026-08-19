"""Sequential verification-first runtime over provider-neutral agent claims."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from verification_harness.actions import ActionGate, ActionRequest
from verification_harness.authority import EvidenceAuthority
from verification_harness.challenges import (
    ChallengeSchedule,
    ChallengeScheduler,
    ChallengeSelection,
    RuntimeChallengePolicy,
)
from verification_harness.decision import Observation, VerificationObligation
from verification_harness.evidence import EvidenceBundle
from verification_harness.gate import VerifiedArtifact
from verification_harness.kernel import VerificationKernel
from verification_harness.persistence import SQLiteRunStore
from verification_harness.protocol import (
    AgentRole,
    AuthorizedSpec,
    ClaimEnvelope,
    RunContext,
    SpecProposal,
    Verdict,
)
from verification_harness.providers import AgentOutput, AgentProvider, AgentRequest
from verification_harness.receipts import DecisionReceipt
from verification_harness.verifiers import VerifierRegistry


def _safe_error(error: BaseException) -> str:
    try:
        message = str(error)
    except BaseException:
        message = "unreadable error"
    return f"{type(error).__name__}: {message}"[:500]


@dataclass(frozen=True)
class RuntimeChallenge:
    """Public metadata for a quarantined critic claim; no rationale propagates."""

    claim_id: str
    claim_digest: str
    selected_obligation_ids: tuple[str, ...]


@dataclass(frozen=True)
class RuntimeAttempt:
    """Attempt metadata; failed attempts intentionally expose no claim payload."""

    attempt: int
    claim_id: str
    claim_digest: str
    verdict: str
    receipt: DecisionReceipt
    artifact: VerifiedArtifact | None
    challenge: RuntimeChallenge | None = None


@dataclass(frozen=True)
class RuntimeResult:
    """A completed bounded run; only ``artifact`` carries an approved payload."""

    context: RunContext
    spec: AuthorizedSpec
    attempts: tuple[RuntimeAttempt, ...]
    verdict: str
    artifact: VerifiedArtifact | None


class AgentInvocationError(RuntimeError):
    """The provider failed before a valid claim could enter quarantine."""


class VerificationRuntime:
    """Generate, quarantine, verify, repair, and gate one sequential workflow."""

    def __init__(
        self,
        *,
        kernel: VerificationKernel,
        evidence_authority: EvidenceAuthority,
        verifier_registry: VerifierRegistry,
        action_gate: ActionGate,
        run_store: SQLiteRunStore,
    ) -> None:
        if kernel.__class__ is not VerificationKernel:
            raise TypeError("verification runtime requires VerificationKernel")
        if verifier_registry.__class__ is not VerifierRegistry:
            raise TypeError("verification runtime requires VerifierRegistry")
        if action_gate.__class__ is not ActionGate:
            raise TypeError("verification runtime requires ActionGate")
        if run_store.__class__ is not SQLiteRunStore:
            raise TypeError("verification runtime requires SQLiteRunStore")
        verifier_id = evidence_authority.verifier_id
        if verifier_id.__class__ is not str or not verifier_id.strip():
            raise ValueError("evidence authority verifier_id must be a non-empty string")
        if not callable(evidence_authority.issue) or not callable(evidence_authority.verify):
            raise TypeError("evidence authority must issue and verify evidence")
        if verifier_id != verifier_registry.verifier_id:
            raise ValueError("evidence authority and verifier registry identity mismatch")
        if verifier_id != kernel.evidence_verifier.verifier_id:
            raise ValueError("evidence authority and kernel verifier identity mismatch")
        self._kernel = kernel
        self._evidence_authority = evidence_authority
        self._verifier_registry = verifier_registry
        self._action_gate = action_gate
        self._run_store = run_store

    def run(
        self,
        *,
        proposal: SpecProposal,
        provider: AgentProvider,
        input_payload: Any,
        obligations: tuple[VerificationObligation, ...],
        role: AgentRole = AgentRole.WORKER,
        max_repairs: int = 0,
        critic_provider: AgentProvider | None = None,
        challenge_obligations: tuple[VerificationObligation, ...] = (),
        challenge_policy: RuntimeChallengePolicy | None = None,
    ) -> RuntimeResult:
        if proposal.__class__ is not SpecProposal:
            raise TypeError("verification runtime requires SpecProposal")
        provider_id = provider.provider_id
        if provider_id.__class__ is not str or not provider_id.strip():
            raise ValueError("agent provider_id must be a non-empty string")
        if not callable(provider.invoke):
            raise TypeError("agent provider must provide invoke")
        if obligations.__class__ is not tuple or not obligations:
            raise ValueError("verification runtime requires non-empty obligations")
        if any(item.__class__ is not VerificationObligation for item in obligations):
            raise TypeError("verification runtime obligations contain an invalid value")
        if role.__class__ is not AgentRole:
            raise TypeError("verification runtime role must be AgentRole")
        if max_repairs.__class__ is not int or max_repairs < 0:
            raise ValueError("max_repairs must be a non-negative integer")
        if challenge_obligations.__class__ is not tuple:
            raise TypeError("challenge_obligations must be a tuple")
        if any(
            item.__class__ is not VerificationObligation for item in challenge_obligations
        ):
            raise TypeError("challenge_obligations contain an invalid value")
        selected_challenge_policy = (
            RuntimeChallengePolicy() if challenge_policy is None else challenge_policy
        )
        if selected_challenge_policy.__class__ is not RuntimeChallengePolicy:
            raise TypeError("challenge_policy must be RuntimeChallengePolicy")
        challenge_scheduler: ChallengeScheduler | None = None
        if critic_provider is None:
            if challenge_obligations:
                raise ValueError("challenge obligations require a critic provider")
        else:
            if role is not AgentRole.WORKER:
                raise ValueError("challenged workflows require the WORKER role")
            if not challenge_obligations:
                raise ValueError("critic provider requires non-empty challenge obligations")
            critic_provider_id = critic_provider.provider_id
            if critic_provider_id.__class__ is not str or not critic_provider_id.strip():
                raise ValueError("critic provider_id must be a non-empty string")
            if not callable(critic_provider.invoke):
                raise TypeError("critic provider must provide invoke")
            if (
                selected_challenge_policy.require_distinct_provider
                and critic_provider_id == provider_id
            ):
                raise ValueError("worker and critic providers must be distinct")
            selected_challenge_policy.authorize(
                worker_provider_id=provider_id,
                critic_provider_id=critic_provider_id,
                baseline=obligations,
                catalog=challenge_obligations,
                selection=ChallengeSelection(
                    selected_obligation_ids=(),
                    rationale={"preflight": True},
                ),
            )
            challenge_scheduler = ChallengeScheduler(
                action_gate=self._action_gate,
                run_store=self._run_store,
                policy=selected_challenge_policy,
            )

        context = self._kernel.open_run(proposal.task_id)
        self._run_store.save_context(context)
        spec = self._kernel.authorize(proposal)
        self._run_store.save_authorized_spec(context.run_id, spec)

        attempts: list[RuntimeAttempt] = []
        feedback: Any = {}
        parent_claim_ids: tuple[str, ...] = ()
        agent_input = {
            "authorized_spec": spec.proposal.to_dict(),
            "task_input": input_payload,
        }
        for attempt_number in range(1, max_repairs + 2):
            request = AgentRequest(
                context=context,
                authorized_spec_digest=spec.digest,
                role=role,
                attempt=attempt_number,
                input_payload=agent_input,
                feedback=feedback,
                parent_claim_ids=parent_claim_ids,
            )
            action = ActionRequest.create(
                run_id=context.run_id,
                actor_id=provider_id,
                kind="agent.invoke",
                target=provider_id,
                payload=request.to_dict(),
            )

            def invoke_provider(current_request: AgentRequest = request) -> AgentOutput:
                return provider.invoke(current_request)

            try:
                output = self._action_gate.execute(
                    action,
                    invoke_provider,
                )
            except (KeyboardInterrupt, GeneratorExit):
                raise
            except BaseException as error:
                raise AgentInvocationError(
                    f"agent provider failed before claim creation: {_safe_error(error)}"
                ) from error
            if output.__class__ is not AgentOutput:
                raise AgentInvocationError("agent provider returned an invalid output")

            claim = ClaimEnvelope.create(
                context=context,
                role=role,
                producer_id=provider_id,
                payload_type=output.payload_type,
                payload=output.payload,
                parent_claim_ids=parent_claim_ids,
                attempt=attempt_number,
            )
            self._run_store.quarantine_claim(claim)
            verification_obligations = obligations
            runtime_challenge: RuntimeChallenge | None = None
            if challenge_scheduler is not None:
                if critic_provider is None:
                    raise AssertionError("challenge scheduler lost its critic provider")
                schedule: ChallengeSchedule = challenge_scheduler.schedule(
                    context=context,
                    spec=spec,
                    worker_claim=claim,
                    worker_provider_id=provider_id,
                    critic_provider=critic_provider,
                    attempt=attempt_number,
                    baseline=obligations,
                    catalog=challenge_obligations,
                )
                verification_obligations = schedule.obligations
                runtime_challenge = RuntimeChallenge(
                    claim_id=schedule.claim_id,
                    claim_digest=schedule.claim_digest,
                    selected_obligation_ids=schedule.selected_obligation_ids,
                )
            observations = self._verifier_registry.collect(
                context,
                spec,
                claim,
                verification_obligations,
            )
            evidence = self._evidence_authority.issue(
                context,
                spec,
                claim,
                verification_obligations,
                observations,
            )
            self._validate_evidence_plan(
                evidence,
                verification_obligations,
                observations,
            )
            self._run_store.save_evidence(evidence)
            decision = self._kernel.evaluate(context, spec, claim, evidence)
            self._run_store.save_receipt(decision.receipt)
            if decision.artifact is not None:
                self._run_store.save_artifact(decision.artifact)
            attempt = RuntimeAttempt(
                attempt=attempt_number,
                claim_id=claim.claim_id,
                claim_digest=claim.digest,
                verdict=decision.verdict,
                receipt=decision.receipt,
                artifact=decision.artifact,
                challenge=runtime_challenge,
            )
            attempts.append(attempt)
            if decision.artifact is not None or decision.verdict != Verdict.REJECTED.value:
                return RuntimeResult(
                    context=context,
                    spec=spec,
                    attempts=tuple(attempts),
                    verdict=decision.verdict,
                    artifact=decision.artifact,
                )
            if attempt_number > max_repairs:
                return RuntimeResult(
                    context=context,
                    spec=spec,
                    attempts=tuple(attempts),
                    verdict=decision.verdict,
                    artifact=None,
                )
            feedback = {
                "failed_claim": claim.to_dict(),
                "observations": [item.to_dict() for item in observations],
                "verdict": decision.verdict,
            }
            parent_claim_ids = (claim.claim_id,)

        raise AssertionError("bounded verification loop exhausted unexpectedly")

    def _validate_evidence_plan(
        self,
        evidence: EvidenceBundle,
        obligations: tuple[VerificationObligation, ...],
        observations: tuple[Observation, ...],
    ) -> None:
        if evidence.__class__ is not EvidenceBundle:
            raise TypeError("evidence authority returned an invalid bundle")
        if evidence.obligations != obligations or evidence.observations != observations:
            raise ValueError("evidence authority changed the verification plan or observations")
        verified = self._evidence_authority.verify(evidence)
        if verified.__class__ is not bool:
            raise TypeError("evidence authority verifier must return bool")
        if not verified:
            raise ValueError("evidence authority returned an invalid signature")
