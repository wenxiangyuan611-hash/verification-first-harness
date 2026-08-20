"""Policy-bounded challenge scheduling for untrusted critic providers."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from verification_harness.actions import ActionGate, ActionRequest
from verification_harness.decision import VerificationObligation
from verification_harness.persistence import SQLiteRunStore
from verification_harness.protocol import AgentRole, AuthorizedSpec, ClaimEnvelope, RunContext
from verification_harness.providers import AgentOutput, AgentProvider, AgentRequest
from verification_harness.schema import canonical_json

CHALLENGE_PAYLOAD_TYPE = (
    "application/vnd.verification-first.challenge-selection+json"
)


def _require_text(name: str, value: object) -> None:
    if value.__class__ is not str or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _safe_error(error: BaseException) -> str:
    try:
        message = str(error)
    except BaseException:
        message = "unreadable error"
    return f"{type(error).__name__}: {message}"[:500]


@dataclass(frozen=True, init=False)
class ChallengeSelection:
    """A detached critic proposal with no verification or propagation authority."""

    selected_obligation_ids: tuple[str, ...]
    _rationale_json: str = field(repr=False)

    def __init__(
        self,
        *,
        selected_obligation_ids: tuple[str, ...],
        rationale: Any,
    ) -> None:
        if selected_obligation_ids.__class__ is not tuple:
            raise TypeError("selected_obligation_ids must be a tuple")
        if any(
            value.__class__ is not str or not value.strip()
            for value in selected_obligation_ids
        ):
            raise ValueError("selected obligation IDs must be non-empty strings")
        if len(selected_obligation_ids) != len(set(selected_obligation_ids)):
            raise ValueError("selected obligation IDs must be unique")
        object.__setattr__(self, "selected_obligation_ids", selected_obligation_ids)
        object.__setattr__(self, "_rationale_json", canonical_json(rationale))

    @property
    def rationale(self) -> Any:
        return json.loads(self._rationale_json)

    def to_dict(self) -> dict[str, Any]:
        return {
            "selected_obligation_ids": list(self.selected_obligation_ids),
            "rationale": self.rationale,
        }

    @classmethod
    def from_output(cls, output: AgentOutput) -> ChallengeSelection:
        if output.__class__ is not AgentOutput:
            raise TypeError("challenge selection requires AgentOutput")
        if output.payload_type != CHALLENGE_PAYLOAD_TYPE:
            raise ValueError("critic returned an unsupported challenge payload type")
        payload = output.payload
        if payload.__class__ is not dict:
            raise ValueError("challenge payload must be a JSON object")
        if set(payload) != {"selected_obligation_ids", "rationale"}:
            raise ValueError(
                "challenge payload must contain exactly selected_obligation_ids and rationale"
            )
        raw_ids = payload["selected_obligation_ids"]
        if raw_ids.__class__ is not list:
            raise ValueError("selected_obligation_ids must be a JSON array")
        return cls(
            selected_obligation_ids=tuple(raw_ids),
            rationale=payload["rationale"],
        )


class RuntimeChallengePolicyError(ValueError):
    """The critic proposal exceeded its pre-authorized influence boundary."""


@dataclass(frozen=True)
class RuntimeChallengePolicy:
    """Authorize only bounded selections from a controller-owned check catalog."""

    max_selected_obligations: int = 8
    max_rationale_bytes: int = 16_384
    require_distinct_provider: bool = True

    def __post_init__(self) -> None:
        if (
            self.max_selected_obligations.__class__ is not int
            or self.max_selected_obligations < 0
        ):
            raise ValueError("max_selected_obligations must be a non-negative integer")
        if self.max_rationale_bytes.__class__ is not int or self.max_rationale_bytes < 1:
            raise ValueError("max_rationale_bytes must be positive")
        if self.require_distinct_provider.__class__ is not bool:
            raise TypeError("require_distinct_provider must be bool")

    def authorize(
        self,
        *,
        worker_provider_id: str,
        critic_provider_id: str,
        baseline: tuple[VerificationObligation, ...],
        catalog: tuple[VerificationObligation, ...],
        selection: ChallengeSelection,
    ) -> tuple[VerificationObligation, ...]:
        _require_text("worker_provider_id", worker_provider_id)
        _require_text("critic_provider_id", critic_provider_id)
        if self.require_distinct_provider and worker_provider_id == critic_provider_id:
            raise RuntimeChallengePolicyError("worker and critic providers must be distinct")
        if baseline.__class__ is not tuple or not baseline:
            raise RuntimeChallengePolicyError(
                "baseline obligations must be a non-empty tuple"
            )
        if catalog.__class__ is not tuple:
            raise RuntimeChallengePolicyError("challenge catalog must be a tuple")
        if any(item.__class__ is not VerificationObligation for item in (*baseline, *catalog)):
            raise RuntimeChallengePolicyError(
                "challenge policy received an invalid obligation"
            )
        if selection.__class__ is not ChallengeSelection:
            raise RuntimeChallengePolicyError(
                "challenge policy received an invalid selection"
            )
        if len(selection.selected_obligation_ids) > self.max_selected_obligations:
            raise RuntimeChallengePolicyError(
                "critic selected too many challenge obligations"
            )
        if len(canonical_json(selection.rationale).encode("utf-8")) > self.max_rationale_bytes:
            raise RuntimeChallengePolicyError(
                "critic rationale exceeded the configured limit"
            )

        baseline_ids = {item.id for item in baseline}
        catalog_by_id = {item.id: item for item in catalog}
        if len(baseline_ids) != len(baseline):
            raise RuntimeChallengePolicyError("baseline obligation IDs must be unique")
        if len(catalog_by_id) != len(catalog):
            raise RuntimeChallengePolicyError(
                "challenge catalog obligation IDs must be unique"
            )
        overlap = baseline_ids & set(catalog_by_id)
        if overlap:
            raise RuntimeChallengePolicyError(
                "challenge catalog cannot replace baseline obligations"
            )
        unknown = set(selection.selected_obligation_ids) - set(catalog_by_id)
        if unknown:
            joined = ", ".join(sorted(unknown))
            raise RuntimeChallengePolicyError(
                f"critic selected unauthorized obligations: {joined}"
            )

        selected_ids = set(selection.selected_obligation_ids)
        selected = tuple(item for item in catalog if item.id in selected_ids)
        return baseline + selected


@dataclass(frozen=True)
class ChallengeSchedule:
    """Controller metadata for one quarantined critic claim and authorized plan."""

    claim_id: str
    claim_digest: str
    selected_obligation_ids: tuple[str, ...]
    obligations: tuple[VerificationObligation, ...]


class ChallengeInvocationError(RuntimeError):
    """A critic failed before a policy-authorized challenge plan was produced."""


class ChallengeScheduler:
    """Invoke an untrusted critic and constrain its influence to check selection."""

    def __init__(
        self,
        *,
        action_gate: ActionGate,
        run_store: SQLiteRunStore,
        policy: RuntimeChallengePolicy | None = None,
    ) -> None:
        if action_gate.__class__ is not ActionGate:
            raise TypeError("challenge scheduler requires ActionGate")
        if run_store.__class__ is not SQLiteRunStore:
            raise TypeError("challenge scheduler requires SQLiteRunStore")
        selected_policy = RuntimeChallengePolicy() if policy is None else policy
        if selected_policy.__class__ is not RuntimeChallengePolicy:
            raise TypeError("challenge scheduler requires RuntimeChallengePolicy")
        self._action_gate = action_gate
        self._run_store = run_store
        self._policy = selected_policy

    def schedule(
        self,
        *,
        context: RunContext,
        spec: AuthorizedSpec,
        worker_claim: ClaimEnvelope,
        worker_provider_id: str,
        critic_provider: AgentProvider,
        attempt: int,
        baseline: tuple[VerificationObligation, ...],
        catalog: tuple[VerificationObligation, ...],
    ) -> ChallengeSchedule:
        if context.__class__ is not RunContext:
            raise TypeError("challenge scheduler requires RunContext")
        if spec.__class__ is not AuthorizedSpec:
            raise TypeError("challenge scheduler requires AuthorizedSpec")
        if worker_claim.__class__ is not ClaimEnvelope:
            raise TypeError("challenge scheduler requires ClaimEnvelope")
        critic_provider_id = critic_provider.provider_id
        _require_text("critic provider_id", critic_provider_id)
        if not callable(critic_provider.invoke):
            raise TypeError("critic provider must provide invoke")

        request = AgentRequest(
            context=context,
            authorized_spec_digest=spec.digest,
            role=AgentRole.CRITIC,
            attempt=attempt,
            input_payload={
                "authorized_spec": spec.proposal.to_dict(),
                "candidate_claim": worker_claim.to_dict(),
                "challenge_contract": {
                    "payload_type": CHALLENGE_PAYLOAD_TYPE,
                    "required_payload_keys": ["selected_obligation_ids", "rationale"],
                    "allowed_obligations": [
                        {
                            "id": item.id,
                            "kind": item.kind,
                            "description": item.description,
                            "criterion_ids": list(item.criterion_ids),
                        }
                        for item in catalog
                    ],
                    "instruction": (
                        "Try to falsify the candidate. Select only checks from the allowed "
                        "catalog. An empty selection is permitted. Your rationale remains "
                        "an untrusted claim and cannot decide the verdict."
                    ),
                },
            },
            parent_claim_ids=(worker_claim.claim_id,),
        )
        action = ActionRequest.create(
            run_id=context.run_id,
            actor_id=critic_provider_id,
            kind="agent.challenge",
            target=critic_provider_id,
            payload=request.to_dict(),
        )

        def invoke_critic() -> AgentOutput:
            return critic_provider.invoke(request)

        try:
            output = self._action_gate.execute(action, invoke_critic)
        except (KeyboardInterrupt, GeneratorExit):
            raise
        except BaseException as error:
            raise ChallengeInvocationError(
                f"critic provider failed before challenge creation: {_safe_error(error)}"
            ) from error
        if output.__class__ is not AgentOutput:
            raise ChallengeInvocationError("critic provider returned an invalid output")

        critic_claim = ClaimEnvelope.create(
            context=context,
            role=AgentRole.CRITIC,
            producer_id=critic_provider_id,
            payload_type=output.payload_type,
            payload=output.payload,
            parent_claim_ids=(worker_claim.claim_id,),
            attempt=attempt,
        )
        self._run_store.quarantine_claim(critic_claim)
        try:
            selection = ChallengeSelection.from_output(output)
            obligations = self._policy.authorize(
                worker_provider_id=worker_provider_id,
                critic_provider_id=critic_provider_id,
                baseline=baseline,
                catalog=catalog,
                selection=selection,
            )
        except (TypeError, ValueError) as error:
            raise ChallengeInvocationError(
                f"critic challenge failed closed: {_safe_error(error)}"
            ) from error
        return ChallengeSchedule(
            claim_id=critic_claim.claim_id,
            claim_digest=critic_claim.digest,
            selected_obligation_ids=selection.selected_obligation_ids,
            obligations=obligations,
        )
