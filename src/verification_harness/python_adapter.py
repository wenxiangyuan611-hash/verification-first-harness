"""Compatibility bridge from the v0.1 Python domain to the generic trust kernel."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from typing import Any

from verification_harness.authority import (
    EvidenceAuthority,
    HMACEvidenceAuthority,
    HMACReceiptAuthority,
    HMACSpecAuthority,
)
from verification_harness.decision import Observation, VerificationObligation
from verification_harness.evidence import EvidenceBundle
from verification_harness.kernel import VerificationKernel
from verification_harness.protocol import (
    AcceptanceCriterion,
    AgentRole,
    AuthorizedSpec,
    ClaimEnvelope,
    EvidenceStatus,
    RunContext,
    SpecProposal,
)
from verification_harness.schema import (
    Claim,
    Spec,
    VerificationReceipt,
    VerificationStatus,
    digest_value,
)


def _criteria(spec: Spec) -> tuple[AcceptanceCriterion, ...]:
    return tuple(
        AcceptanceCriterion(f"requirement-{index:04d}", requirement)
        for index, requirement in enumerate(spec.requirements, start=1)
    )


def _spec_payload(spec: Spec) -> dict[str, Any]:
    return {
        "description": spec.description,
        "entrypoint": spec.entrypoint,
        "tests": [
            {"id": item.id, "input": item.input, "expected": item.expected}
            for item in spec.test_cases
        ],
    }


def _contract_digest(
    task_id: str,
    domain: str,
    criteria: tuple[AcceptanceCriterion, ...],
    payload: Any,
) -> str:
    return digest_value(
        {
            "task_id": task_id,
            "domain": domain,
            "criteria": [item.to_dict() for item in criteria],
            "payload": payload,
        }
    )


def spec_to_proposal(
    context: RunContext,
    spec: Spec,
    proposer_id: str,
) -> SpecProposal:
    return SpecProposal(
        proposal_id=f"{context.run_id}:spec",
        task_id=spec.task_id,
        proposer_id=proposer_id,
        domain="python.function",
        criteria=_criteria(spec),
        payload=_spec_payload(spec),
    )


def registered_task_policy(planner: object) -> Callable[[SpecProposal], bool]:
    """Snapshot the deterministic registry treated as authorized out of band in v0.1."""
    registry = getattr(planner, "task_registry", None)
    allowed: dict[str, str] = {}
    if registry.__class__ is dict:
        for task_id, task in registry.items():
            try:
                spec = Spec(
                    task_id,
                    task.description,
                    task.requirements,
                    task.test_cases,
                    task.entrypoint,
                )
            except (AttributeError, TypeError, ValueError):
                continue
            allowed[task_id] = _contract_digest(
                task_id,
                "python.function",
                _criteria(spec),
                _spec_payload(spec),
            )

    def approve(proposal: SpecProposal) -> bool:
        proposed = _contract_digest(
            proposal.task_id,
            proposal.domain,
            proposal.criteria,
            proposal.payload,
        )
        return allowed.get(proposal.task_id) == proposed

    return approve


def compatibility_kernel(
    planner: object,
) -> tuple[VerificationKernel, EvidenceAuthority]:
    """Create isolated process-local authorities for the deterministic legacy registry."""
    evidence_authority = HMACEvidenceAuthority(
        "legacy-python-verifier-bridge",
        secrets.token_bytes(32),
    )
    kernel = VerificationKernel(
        spec_authority=HMACSpecAuthority(
            "legacy-registry-authority",
            secrets.token_bytes(32),
            registered_task_policy(planner),
        ),
        evidence_verifier=evidence_authority,
        receipt_authority=HMACReceiptAuthority(
            "legacy-controller-receipt-authority",
            secrets.token_bytes(32),
        ),
    )
    return kernel, evidence_authority


def claim_to_envelope(
    context: RunContext,
    claim: Claim,
    parent_claim_ids: tuple[str, ...] = (),
) -> ClaimEnvelope:
    return ClaimEnvelope(
        claim_id=f"{context.run_id}:claim:{claim.attempt}:{claim.digest}",
        run_id=context.run_id,
        role=AgentRole.WORKER,
        producer_id=claim.worker_id,
        payload_type="python.source",
        payload={"code": claim.code, "description": claim.description},
        parent_claim_ids=parent_claim_ids,
        attempt=claim.attempt,
    )


def receipt_to_evidence_bundle(
    authority: EvidenceAuthority,
    context: RunContext,
    spec: AuthorizedSpec,
    claim: ClaimEnvelope,
    receipt: VerificationReceipt,
) -> EvidenceBundle:
    """Bridge an already authenticated legacy receipt into generic evidence."""
    criterion_ids = tuple(item.id for item in spec.proposal.criteria)
    obligations = tuple(
        VerificationObligation(
            id=item.id,
            kind=f"python.{item.kind.lower()}",
            description=item.description,
            criterion_ids=criterion_ids,
            payload=item.payload,
        )
        for item in receipt.obligations
    )
    observations = tuple(
        Observation(
            obligation_id=item.obligation_id,
            status=(
                EvidenceStatus.PASSED
                if item.status is VerificationStatus.PASSED
                else EvidenceStatus.FAILED
            ),
            observed=item.observed,
            expected=item.expected_repr,
            error=item.error,
        )
        for item in receipt.evidence
    )
    return authority.issue(context, spec, claim, obligations, observations)
